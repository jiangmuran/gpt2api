package user

import (
	"context"
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/432539/gpt2api/internal/audit"
	"github.com/432539/gpt2api/internal/billing"
	"github.com/432539/gpt2api/internal/middleware"
	"github.com/432539/gpt2api/pkg/resp"
)

// PasswordService 由 auth 包实现。通过接口解耦,避免 user<->auth 循环依赖。
type PasswordService interface {
	HashPassword(plain string) (string, error)
	VerifyPassword(ctx context.Context, userID uint64, password string) error
}

// AdminHandler 管理员视角下的用户管理接口。
type AdminHandler struct {
	dao      *DAO
	auth     PasswordService
	billing  *billing.Engine
	auditDAO *audit.DAO
}

// NewAdminHandler 构造。
func NewAdminHandler(dao *DAO, authSvc PasswordService, bill *billing.Engine, auditDAO *audit.DAO) *AdminHandler {
	return &AdminHandler{dao: dao, auth: authSvc, billing: bill, auditDAO: auditDAO}
}

// List GET /api/admin/users
func (h *AdminHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	groupID, _ := strconv.ParseUint(c.Query("group_id"), 10, 64)

	items, total, err := h.dao.ListPage(c.Request.Context(), ListFilter{
		Keyword: c.Query("q"),
		Role:    c.Query("role"),
		Status:  c.Query("status"),
		GroupID: groupID,
	}, limit, offset)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"items": items, "total": total, "limit": limit, "offset": offset})
}

// Get GET /api/admin/users/:id
func (h *AdminHandler) Get(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	u, err := h.dao.GetByID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			resp.NotFound(c, "user not found")
			return
		}
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, u)
}

// updateReq PATCH /api/admin/users/:id 的 body。全部字段可选。
type updateReq struct {
	Nickname *string `json:"nickname,omitempty"`
	Role     *string `json:"role,omitempty"`
	Status   *string `json:"status,omitempty"`
	GroupID  *uint64 `json:"group_id,omitempty"`
}

// Update PATCH /api/admin/users/:id
func (h *AdminHandler) Update(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	var req updateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	// 防自我锁死:不允许把自己从 admin 改成 user(避免最后一个 admin 流失)
	actor := middleware.UserID(c)
	if req.Role != nil && *req.Role != "admin" && id == actor {
		resp.BadRequest(c, "cannot downgrade your own admin role")
		return
	}

	n, err := h.dao.Update(c.Request.Context(), id, UpdatePatch{
		Nickname: req.Nickname,
		Role:     req.Role,
		Status:   req.Status,
		GroupID:  req.GroupID,
	})
	if err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if n == 0 {
		resp.NotFound(c, "user not found")
		return
	}
	audit.Record(c, h.auditDAO, "users.update", strconv.FormatUint(id, 10), req)
	resp.OK(c, gin.H{"updated": n})
}

// resetPwdReq 重置密码的 body。
type resetPwdReq struct {
	NewPassword   string `json:"new_password" binding:"required,min=6"`
	AdminPassword string `json:"admin_password" binding:"required"`
}

// ResetPassword POST /api/admin/users/:id/reset-password
// 高危:必须提供 admin_password(或 X-Admin-Confirm header)。
func (h *AdminHandler) ResetPassword(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	var req resetPwdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	actor := middleware.UserID(c)
	if err := h.auth.VerifyPassword(c.Request.Context(), actor, req.AdminPassword); err != nil {
		resp.Forbidden(c, "admin password mismatch")
		return
	}
	hash, err := h.auth.HashPassword(req.NewPassword)
	if err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if err := h.dao.ResetPassword(c.Request.Context(), id, hash); err != nil {
		if errors.Is(err, ErrNotFound) {
			resp.NotFound(c, "user not found")
			return
		}
		resp.InternalErr(c, err)
		return
	}
	audit.Record(c, h.auditDAO, "users.reset_password", strconv.FormatUint(id, 10), nil)
	resp.OK(c, gin.H{"ok": true})
}

// Delete DELETE /api/admin/users/:id (软删除)
// 禁止删除自己;高危,需二次密码。
func (h *AdminHandler) Delete(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	actor := middleware.UserID(c)
	if id == actor {
		resp.BadRequest(c, "cannot delete yourself")
		return
	}
	if err := confirmAdmin(c, h.auth); err != nil {
		resp.Forbidden(c, err.Error())
		return
	}
	if err := h.dao.SoftDelete(c.Request.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			resp.NotFound(c, "user not found")
			return
		}
		resp.InternalErr(c, err)
		return
	}
	audit.Record(c, h.auditDAO, "users.delete", strconv.FormatUint(id, 10), nil)
	resp.OK(c, gin.H{"deleted": id})
}

// adjustReq 调账 body。
type adjustReq struct {
	Delta  int64  `json:"delta" binding:"required"` // 可正可负,单位 credit(厘)
	Remark string `json:"remark" binding:"required,min=1,max=200"`
	RefID  string `json:"ref_id"`
}

// Adjust POST /api/admin/users/:id/credits/adjust
// 需 user:credit 权限 + 二次密码(X-Admin-Confirm 或 body.admin_password)。
func (h *AdminHandler) Adjust(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	var req adjustReq
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if req.Delta == 0 {
		resp.BadRequest(c, "delta must not be zero")
		return
	}
	if err := confirmAdmin(c, h.auth); err != nil {
		resp.Forbidden(c, err.Error())
		return
	}

	actor := middleware.UserID(c)
	balance, err := h.billing.AdminAdjust(c.Request.Context(), id, actor, req.Delta, req.RefID, req.Remark)
	if err != nil {
		audit.Record(c, h.auditDAO, "users.credit.adjust.failed",
			strconv.FormatUint(id, 10), gin.H{"delta": req.Delta, "error": err.Error()})
		if errors.Is(err, billing.ErrInsufficient) {
			resp.BadRequest(c, "积分不足")
			return
		}
		resp.InternalErr(c, err)
		return
	}
	audit.Record(c, h.auditDAO, "users.credit.adjust", strconv.FormatUint(id, 10),
		gin.H{"delta": req.Delta, "balance_after": balance, "remark": req.Remark, "ref_id": req.RefID})
	resp.OK(c, gin.H{"balance_after": balance, "delta": req.Delta})
}

// CreditLogs GET /api/admin/users/:id/credit-logs
func (h *AdminHandler) CreditLogs(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	items, total, err := h.dao.ListCreditLogs(c.Request.Context(), id, limit, offset)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"items": items, "total": total, "limit": limit, "offset": offset})
}

// ---- 积分管理(全局视图) ----

// CreditLogsGlobal GET /api/admin/credits/logs
// 查询全站流水,支持 user_id/keyword(匹配 email/nickname)/type/sign/start_at/end_at 过滤。
func (h *AdminHandler) CreditLogsGlobal(c *gin.Context) {
	userID, _ := strconv.ParseUint(c.DefaultQuery("user_id", "0"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	f := CreditLogFilter{
		UserID:  userID,
		Keyword: c.Query("keyword"),
		Type:    c.Query("type"),
		Sign:    c.Query("sign"),
		StartAt: c.Query("start_at"),
		EndAt:   c.Query("end_at"),
	}
	items, total, err := h.dao.ListCreditLogsGlobal(c.Request.Context(), f, limit, offset)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{
		"items":  items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// CreditsSummary GET /api/admin/credits/summary
// 返回今日/7 天/累计 入账/消耗 以及全站总余额。
func (h *AdminHandler) CreditsSummary(c *gin.Context) {
	s, err := h.dao.CreditSummary(c.Request.Context())
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, s)
}

// AdjustByUser POST /api/admin/credits/adjust
// 以 body.user_id 指定用户进行调账,相当于 /users/:id/credits/adjust 的全局入口。
func (h *AdminHandler) AdjustByUser(c *gin.Context) {
	var req struct {
		UserID uint64 `json:"user_id" binding:"required"`
		Delta  int64  `json:"delta"   binding:"required"`
		Remark string `json:"remark"  binding:"required,min=1,max=200"`
		RefID  string `json:"ref_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	if req.Delta == 0 {
		resp.BadRequest(c, "delta 不能为 0")
		return
	}
	if err := confirmAdmin(c, h.auth); err != nil {
		resp.Forbidden(c, err.Error())
		return
	}
	actor := middleware.UserID(c)
	balance, err := h.billing.AdminAdjust(c.Request.Context(), req.UserID, actor, req.Delta, req.RefID, req.Remark)
	if err != nil {
		audit.Record(c, h.auditDAO, "users.credit.adjust.failed",
			strconv.FormatUint(req.UserID, 10),
			gin.H{"delta": req.Delta, "error": err.Error()})
		if errors.Is(err, billing.ErrInsufficient) {
			resp.BadRequest(c, "余额不足")
			return
		}
		resp.InternalErr(c, err)
		return
	}
	audit.Record(c, h.auditDAO, "users.credit.adjust",
		strconv.FormatUint(req.UserID, 10),
		gin.H{"delta": req.Delta, "balance_after": balance, "remark": req.Remark, "ref_id": req.RefID})
	resp.OK(c, gin.H{"balance_after": balance, "delta": req.Delta})
}

// ---- helpers ----

func parseID(c *gin.Context) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		resp.BadRequest(c, "invalid id")
		return 0, false
	}
	return id, true
}

// confirmAdmin 从 header X-Admin-Confirm 里拿密码做二次校验。
// 如果 handler 自己读到了 body.admin_password,传入 bodyPwd 参数优先使用。
func confirmAdmin(c *gin.Context, authSvc PasswordService) error {
	pwd := c.GetHeader("X-Admin-Confirm")
	if pwd == "" {
		// 回退:从 body/form 尝试
		pwd = c.PostForm("admin_password")
	}
	if pwd == "" {
		return errors.New("X-Admin-Confirm header required for this destructive operation")
	}
	actor := middleware.UserID(c)
	if actor == 0 {
		return errors.New("not authenticated")
	}
	if err := authSvc.VerifyPassword(c.Request.Context(), actor, pwd); err != nil {
		return errors.New("admin password mismatch")
	}
	return nil
}
