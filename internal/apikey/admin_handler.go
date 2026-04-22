package apikey

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/432539/gpt2api/pkg/resp"
)

// AdminHandler 提供跨用户 keys 视角。
// 读操作走新的 list SQL(LEFT JOIN users 带邮箱,便于排查)。
// 写操作(强制禁用 / 删除)复用 apikey.Service 的 Update/Delete,避免重复实现。
type AdminHandler struct {
	svc *Service
	dao *DAO
	db  *sqlx.DB
}

func NewAdminHandler(svc *Service, dao *DAO, db *sqlx.DB) *AdminHandler {
	return &AdminHandler{svc: svc, dao: dao, db: db}
}

// adminKeyRow 带上用户邮箱做联表展示。
type adminKeyRow struct {
	APIKey
	UserEmail string `db:"user_email" json:"user_email"`
}

// GET /api/admin/keys
// query: user_id, enabled, q(name 模糊), limit, offset
func (h *AdminHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if offset < 0 {
		offset = 0
	}

	where := []string{"k.deleted_at IS NULL", "k.name <> ?"}
	args := []any{InternalKeyName}
	if uid, _ := strconv.ParseUint(c.Query("user_id"), 10, 64); uid > 0 {
		where = append(where, "k.user_id = ?")
		args = append(args, uid)
	}
	if v := c.Query("enabled"); v != "" {
		b := v == "1" || strings.EqualFold(v, "true")
		where = append(where, "k.enabled = ?")
		args = append(args, b)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		where = append(where, "(k.name LIKE ? OR k.key_prefix LIKE ? OR u.email LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	ws := strings.Join(where, " AND ")

	query := fmt.Sprintf(`
SELECT k.*, COALESCE(u.email, '') AS user_email
FROM api_keys k
LEFT JOIN users u ON u.id = k.user_id
WHERE %s
ORDER BY k.id DESC
LIMIT ? OFFSET ?`, ws)

	rows := make([]adminKeyRow, 0, limit)
	if err := h.db.SelectContext(c.Request.Context(), &rows, query, append(args, limit, offset)...); err != nil {
		resp.InternalErr(c, err)
		return
	}
	var total int64
	if err := h.db.GetContext(c.Request.Context(), &total,
		fmt.Sprintf(`SELECT COUNT(*) FROM api_keys k LEFT JOIN users u ON u.id = k.user_id WHERE %s`, ws),
		args...); err != nil {
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

// PATCH /api/admin/keys/:id  (目前只支持 enabled)
// 管理员可以强制禁用用户的 key。
func (h *AdminHandler) SetEnabled(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var req struct {
		Enabled *bool `json:"enabled" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	k, err := h.dao.GetByID(c.Request.Context(), id)
	if err != nil {
		resp.NotFound(c, err.Error())
		return
	}
	k.Enabled = *req.Enabled
	if err := h.dao.Update(c.Request.Context(), k); err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"id": id, "enabled": k.Enabled})
}
