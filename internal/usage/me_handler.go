package usage

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/432539/gpt2api/internal/middleware"
	"github.com/432539/gpt2api/pkg/resp"
)

// MeHandler 面向当前用户的 usage 只读接口。
// 与 AdminHandler 的区别:强制注入 UserID = 当前登录用户,
// 客户端不能越权查看他人数据。
type MeHandler struct{ qdao *QueryDAO }

// NewMeHandler 构造。
func NewMeHandler(qdao *QueryDAO) *MeHandler { return &MeHandler{qdao: qdao} }

// filterFromMeQuery 与 admin 版一致,但强制 UserID = current。
func filterFromMeQuery(c *gin.Context, userID uint64) Filter {
	f := Filter{
		UserID: userID,
		Type:   c.Query("type"),
		Status: c.Query("status"),
		Since:  parseFlexTime(c.Query("since")),
		Until:  parseFlexTime(c.Query("until")),
	}
	if mid, err := strconv.ParseUint(c.Query("model_id"), 10, 64); err == nil {
		f.ModelID = mid
	}
	if kid, err := strconv.ParseUint(c.Query("key_id"), 10, 64); err == nil {
		f.KeyID = kid
	}
	return f
}

// GET /api/me/usage/logs
// 返回当前用户的原始日志分页。
func (h *MeHandler) Logs(c *gin.Context) {
	uid := middleware.UserID(c)
	if uid == 0 {
		resp.Unauthorized(c, "not logged in")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit > 200 {
		limit = 200
	}
	f := filterFromMeQuery(c, uid)
	rows, total, err := h.qdao.List(c.Request.Context(), f, offset, limit)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"items": rows, "total": total, "limit": limit, "offset": offset})
}

// GET /api/me/usage/stats
// 返回当前用户的整体汇总 + 最近 N 天折线 + 模型 TOP N。
// 不包括按用户聚合(当前用户视角下无意义)。
func (h *MeHandler) Stats(c *gin.Context) {
	uid := middleware.UserID(c)
	if uid == 0 {
		resp.Unauthorized(c, "not logged in")
		return
	}
	days, _ := strconv.Atoi(c.DefaultQuery("days", "14"))
	topN, _ := strconv.Atoi(c.DefaultQuery("top_n", "5"))
	f := filterFromMeQuery(c, uid)

	overall, err := h.qdao.Overall(c.Request.Context(), f)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	daily, err := h.qdao.Daily(c.Request.Context(), f, days)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	byModel, err := h.qdao.ByModel(c.Request.Context(), f, topN)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{
		"overall":  overall,
		"daily":    daily,
		"by_model": byModel,
	})
}
