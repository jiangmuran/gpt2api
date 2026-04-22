package user

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/432539/gpt2api/internal/middleware"
	"github.com/432539/gpt2api/internal/rbac"
	"github.com/432539/gpt2api/pkg/resp"
)

// Handler 用户相关接口。
type Handler struct {
	dao *DAO
}

func NewHandler(dao *DAO) *Handler { return &Handler{dao: dao} }

// Me 当前登录用户信息。响应同时包含该用户拥有的权限清单(用于前端路由守卫)。
func (h *Handler) Me(c *gin.Context) {
	uid := middleware.UserID(c)
	if uid == 0 {
		resp.Unauthorized(c, "not logged in")
		return
	}
	u, err := h.dao.GetByID(c.Request.Context(), uid)
	if err != nil {
		if err == ErrNotFound {
			resp.NotFound(c, "user not found")
			return
		}
		resp.InternalErr(c, err)
		return
	}
	// 以 DB 中的 role 为准(避免 JWT 中旧 role 泄漏带来的提权)。
	perms := rbac.ListPermissions(u.Role)
	resp.OK(c, gin.H{
		"user":        u,
		"role":        u.Role,
		"permissions": perms,
	})
}

// Menu 返回当前用户可见的菜单树。仅依据 DB 中的 role 计算,前端直接渲染。
func (h *Handler) Menu(c *gin.Context) {
	uid := middleware.UserID(c)
	if uid == 0 {
		resp.Unauthorized(c, "not logged in")
		return
	}
	u, err := h.dao.GetByID(c.Request.Context(), uid)
	if err != nil {
		if err == ErrNotFound {
			resp.NotFound(c, "user not found")
			return
		}
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{
		"role":        u.Role,
		"menu":        rbac.MenuForRole(u.Role),
		"permissions": rbac.ListPermissions(u.Role),
	})
}

// CreditLogs GET /api/me/credit-logs
// 当前登录用户的积分流水(只读、强制 user_id = 当前用户)。
func (h *Handler) CreditLogs(c *gin.Context) {
	uid := middleware.UserID(c)
	if uid == 0 {
		resp.Unauthorized(c, "not logged in")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	items, total, err := h.dao.ListCreditLogs(c.Request.Context(), uid, limit, offset)
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
