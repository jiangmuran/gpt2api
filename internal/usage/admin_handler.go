package usage

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/432539/gpt2api/pkg/resp"
)

// AdminHandler 提供 /api/admin/usage/* 的只读聚合/列表接口。
type AdminHandler struct{ qdao *QueryDAO }

func NewAdminHandler(qdao *QueryDAO) *AdminHandler { return &AdminHandler{qdao: qdao} }

// filterFromQuery 解析通用 query 参数到 Filter。
// 约定:since/until 使用 RFC3339 或 YYYY-MM-DD;不传即无限制。
func filterFromQuery(c *gin.Context) Filter {
	uid64, _ := strconv.ParseUint(c.Query("user_id"), 10, 64)
	mid64, _ := strconv.ParseUint(c.Query("model_id"), 10, 64)
	kid64, _ := strconv.ParseUint(c.Query("key_id"), 10, 64)
	aid64, _ := strconv.ParseUint(c.Query("account_id"), 10, 64)

	return Filter{
		UserID:    uid64,
		KeyID:     kid64,
		ModelID:   mid64,
		AccountID: aid64,
		Type:      c.Query("type"),
		Status:    c.Query("status"),
		Since:     parseFlexTime(c.Query("since")),
		Until:     parseFlexTime(c.Query("until")),
	}
}

func parseFlexTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t
	}
	return time.Time{}
}

// GET /api/admin/usage/stats
// 返回综合聚合:overall + daily 折线 + top model + top user(可控 top_n)
func (h *AdminHandler) Stats(c *gin.Context) {
	f := filterFromQuery(c)
	days, _ := strconv.Atoi(c.DefaultQuery("days", "14"))
	topN, _ := strconv.Atoi(c.DefaultQuery("top_n", "10"))

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
	byUser, err := h.qdao.ByUser(c.Request.Context(), f, topN)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{
		"overall":  overall,
		"daily":    daily,
		"by_model": byModel,
		"by_user":  byUser,
	})
}

// GET /api/admin/usage/logs
// 返回原始日志分页。
func (h *AdminHandler) Logs(c *gin.Context) {
	f := filterFromQuery(c)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	rows, total, err := h.qdao.List(c.Request.Context(), f, offset, limit)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{
		"items":  rows,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}
