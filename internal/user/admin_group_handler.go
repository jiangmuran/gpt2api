package user

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/432539/gpt2api/internal/audit"
	"github.com/432539/gpt2api/pkg/resp"
)

// AdminGroupHandler 管理员视角下的用户分组 CRUD。
type AdminGroupHandler struct {
	dao      *DAO
	auditDAO *audit.DAO
}

// NewAdminGroupHandler 构造。
func NewAdminGroupHandler(dao *DAO, auditDAO *audit.DAO) *AdminGroupHandler {
	return &AdminGroupHandler{dao: dao, auditDAO: auditDAO}
}

// groupReq 创建/更新分组的 body。
type groupReq struct {
	Name              string  `json:"name" binding:"required,min=2,max=64"`
	Ratio             float64 `json:"ratio" binding:"required,gt=0"`
	DailyLimitCredits int64   `json:"daily_limit_credits"`
	RPMLimit          int     `json:"rpm_limit"`
	TPMLimit          int64   `json:"tpm_limit"`
	Remark            string  `json:"remark"`
}

// List GET /api/admin/groups
func (h *AdminGroupHandler) List(c *gin.Context) {
	items, err := h.dao.ListGroups(c.Request.Context())
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"items": items, "total": len(items)})
}

// Create POST /api/admin/groups
func (h *AdminGroupHandler) Create(c *gin.Context) {
	var req groupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	g := &Group{
		Name:              req.Name,
		Ratio:             req.Ratio,
		DailyLimitCredits: req.DailyLimitCredits,
		RPMLimit:          req.RPMLimit,
		TPMLimit:          req.TPMLimit,
		Remark:            req.Remark,
	}
	id, err := h.dao.CreateGroup(c.Request.Context(), g)
	if err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	g.ID = id
	audit.Record(c, h.auditDAO, "groups.create", strconv.FormatUint(id, 10), g)
	resp.OK(c, g)
}

// Update PUT /api/admin/groups/:id
func (h *AdminGroupHandler) Update(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	var req groupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, err.Error())
		return
	}
	g := &Group{
		ID:                id,
		Name:              req.Name,
		Ratio:             req.Ratio,
		DailyLimitCredits: req.DailyLimitCredits,
		RPMLimit:          req.RPMLimit,
		TPMLimit:          req.TPMLimit,
		Remark:            req.Remark,
	}
	if err := h.dao.UpdateGroup(c.Request.Context(), g); err != nil {
		if errors.Is(err, ErrNotFound) {
			resp.NotFound(c, "group not found")
			return
		}
		resp.InternalErr(c, err)
		return
	}
	audit.Record(c, h.auditDAO, "groups.update", strconv.FormatUint(id, 10), g)
	resp.OK(c, g)
}

// Delete DELETE /api/admin/groups/:id
func (h *AdminGroupHandler) Delete(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	if err := h.dao.DeleteGroup(c.Request.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			resp.NotFound(c, "group not found")
			return
		}
		resp.BadRequest(c, err.Error())
		return
	}
	audit.Record(c, h.auditDAO, "groups.delete", strconv.FormatUint(id, 10), nil)
	resp.OK(c, gin.H{"deleted": id})
}
