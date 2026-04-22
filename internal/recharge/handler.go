package recharge

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/432539/gpt2api/internal/middleware"
	"github.com/432539/gpt2api/pkg/resp"
)

// Handler 实现用户/公开 端点。
type Handler struct{ svc *Service }

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// GET /api/recharge/packages
// 返回已启用的套餐 + 通道状态。未登录也可访问(方便前端登录页展示定价)。
func (h *Handler) ListPackages(c *gin.Context) {
	pkgs, err := h.svc.ListEnabledPackages(c.Request.Context())
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{
		"items":          pkgs,
		"enabled":        h.svc.Enabled() && h.svc.AdminEnabled(),
		"channel_ready":  h.svc.Enabled(),
		"admin_enabled":  h.svc.AdminEnabled(),
		"min_cny":        h.svc.MinAmountCNY(),
		"max_cny":        h.svc.MaxAmountCNY(),
		"daily_limit":    h.svc.DailyLimitCNY(),
		"expire_minutes": h.svc.OrderExpireMinutes(),
	})
}

// POST /api/recharge/orders
// body: { package_id, pay_type }
func (h *Handler) CreateOrder(c *gin.Context) {
	uid := middleware.UserID(c)
	if uid == 0 {
		resp.Unauthorized(c, "unauthorized")
		return
	}
	var req struct {
		PackageID uint64 `json:"package_id" binding:"required"`
		PayType   string `json:"pay_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	o, err := h.svc.Create(c.Request.Context(), CreateInput{
		UserID:    uid,
		PackageID: req.PackageID,
		PayType:   req.PayType,
		ClientIP:  c.ClientIP(),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrChannelDisabled):
			resp.Fail(c, 40301, "支付通道未配置,请联系管理员")
		case errors.Is(err, ErrRechargeDisabled):
			resp.Forbidden(c, "管理员已关闭充值")
		case errors.Is(err, ErrAmountOutOfRange):
			resp.BadRequest(c, "该套餐金额不在允许的充值范围内")
		case errors.Is(err, ErrDailyLimitExceeded):
			resp.BadRequest(c, "已达到今日累计充值上限")
		case errors.Is(err, ErrPackageUnavailable), errors.Is(err, ErrNotFound):
			resp.NotFound(c, "套餐不存在或已下架")
		default:
			resp.InternalErr(c, err)
		}
		return
	}
	resp.OK(c, o)
}

// GET /api/recharge/orders
func (h *Handler) ListMyOrders(c *gin.Context) {
	uid := middleware.UserID(c)
	if uid == 0 {
		resp.Unauthorized(c, "unauthorized")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	rows, total, err := h.svc.ListUserOrders(c.Request.Context(), uid, c.Query("status"), offset, limit)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"items": rows, "total": total, "limit": limit, "offset": offset})
}

// POST /api/recharge/orders/:id/cancel
func (h *Handler) CancelOrder(c *gin.Context) {
	uid := middleware.UserID(c)
	if uid == 0 {
		resp.Unauthorized(c, "unauthorized")
		return
	}
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if err := h.svc.CancelByUser(c.Request.Context(), uid, id); err != nil {
		switch {
		case errors.Is(err, ErrOrderStateInvalid):
			resp.Conflict(c, "订单状态不可取消")
		case errors.Is(err, ErrOrderNotFound), errors.Is(err, ErrNotFound):
			resp.NotFound(c, "订单不存在")
		default:
			resp.InternalErr(c, err)
		}
		return
	}
	resp.OK(c, gin.H{"ok": true})
}

// ---------- 公开的回调入口(不鉴权,走签名校验) ----------

// POST /api/public/epay/notify
// GET  /api/public/epay/notify
// 按上游 ePay 规范,**响应必须是裸 "success"/"fail" 字符串**,不要被 resp 包装。
func (h *Handler) EPayNotify(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		c.String(200, "fail")
		return
	}
	// ePay 可能 GET 也可能 POST,合并两种 values
	form := c.Request.Form
	text, _ := h.svc.HandleNotify(c.Request.Context(), form)
	c.String(200, text)
}
