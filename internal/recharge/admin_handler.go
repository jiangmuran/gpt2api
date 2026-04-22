package recharge

import (
	"context"
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/432539/gpt2api/internal/middleware"
	"github.com/432539/gpt2api/pkg/resp"
)

// PasswordVerifier 是"校验某 user 是否知道自己密码"的能力。
// auth.Service 隐式实现了这个接口,避免 recharge 直接依赖 auth。
type PasswordVerifier interface {
	VerifyPassword(ctx context.Context, userID uint64, password string) error
}

// AdminHandler 提供管理员侧:套餐 CRUD + 订单查看 + 手工入账。
type AdminHandler struct {
	svc  *Service
	auth PasswordVerifier
}

func NewAdminHandler(svc *Service, auth PasswordVerifier) *AdminHandler {
	return &AdminHandler{svc: svc, auth: auth}
}

// confirmAdmin:从 X-Admin-Confirm header 取明文密码,对当前 admin 再做一次校验。
// 与 user 包同名函数语义一致。
func (h *AdminHandler) confirmAdmin(c *gin.Context) error {
	pwd := c.GetHeader("X-Admin-Confirm")
	if pwd == "" {
		return errors.New("X-Admin-Confirm header required for this destructive operation")
	}
	actor := middleware.UserID(c)
	if actor == 0 {
		return errors.New("not authenticated")
	}
	return h.auth.VerifyPassword(c.Request.Context(), actor, pwd)
}

// GET /api/admin/recharge/packages
func (h *AdminHandler) ListPackages(c *gin.Context) {
	rows, err := h.svc.AdminListPackages(c.Request.Context())
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"items": rows, "total": len(rows)})
}

type pkgReq struct {
	Name        string `json:"name" binding:"required,max=64"`
	PriceCNY    int    `json:"price_cny" binding:"required,min=1"`
	Credits     int64  `json:"credits" binding:"required,min=0"`
	Bonus       int64  `json:"bonus" binding:"min=0"`
	Description string `json:"description" binding:"max=255"`
	Sort        int    `json:"sort"`
	Enabled     bool   `json:"enabled"`
}

// POST /api/admin/recharge/packages
func (h *AdminHandler) CreatePackage(c *gin.Context) {
	var req pkgReq
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	p := &Package{
		Name:        req.Name,
		PriceCNY:    req.PriceCNY,
		Credits:     req.Credits,
		Bonus:       req.Bonus,
		Description: req.Description,
		Sort:        req.Sort,
		Enabled:     req.Enabled,
	}
	id, err := h.svc.AdminCreatePackage(c.Request.Context(), p)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	p.ID = id
	resp.OK(c, p)
}

// PATCH /api/admin/recharge/packages/:id
func (h *AdminHandler) UpdatePackage(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var req pkgReq
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	p := &Package{
		ID:          id,
		Name:        req.Name,
		PriceCNY:    req.PriceCNY,
		Credits:     req.Credits,
		Bonus:       req.Bonus,
		Description: req.Description,
		Sort:        req.Sort,
		Enabled:     req.Enabled,
	}
	if err := h.svc.AdminUpdatePackage(c.Request.Context(), p); err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, p)
}

// DELETE /api/admin/recharge/packages/:id
func (h *AdminHandler) DeletePackage(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if err := h.svc.AdminDeletePackage(c.Request.Context(), id); err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"ok": true})
}

// GET /api/admin/recharge/orders
func (h *AdminHandler) ListOrders(c *gin.Context) {
	uid, _ := strconv.ParseUint(c.Query("user_id"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	rows, total, err := h.svc.AdminListOrders(c.Request.Context(),
		ListFilter{UserID: uid, Status: c.Query("status")}, offset, limit)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"items": rows, "total": total, "limit": limit, "offset": offset})
}

// POST /api/admin/recharge/orders/:id/force-paid
// 管理员应急入账。需要 X-Admin-Confirm。
func (h *AdminHandler) ForcePaid(c *gin.Context) {
	if err := h.confirmAdmin(c); err != nil {
		resp.Forbidden(c, err.Error())
		return
	}
	actorID := middleware.UserID(c)
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if err := h.svc.AdminForcePaid(c.Request.Context(), id, actorID); err != nil {
		switch {
		case errors.Is(err, ErrOrderStateInvalid):
			resp.Conflict(c, "订单状态不是 pending")
		case errors.Is(err, ErrNotFound):
			resp.NotFound(c, "订单不存在")
		default:
			resp.InternalErr(c, err)
		}
		return
	}
	resp.OK(c, gin.H{"ok": true})
}
