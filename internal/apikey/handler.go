package apikey

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/432539/gpt2api/internal/middleware"
	"github.com/432539/gpt2api/pkg/resp"
)

type Handler struct{ svc *Service }

func NewHandler(s *Service) *Handler { return &Handler{svc: s} }

// POST /api/keys
func (h *Handler) Create(c *gin.Context) {
	userID := middleware.UserID(c)
	if userID == 0 {
		resp.Unauthorized(c, "未登录")
		return
	}
	var req CreateInput
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, "请求参数错误:"+err.Error())
		return
	}
	out, err := h.svc.Create(c.Request.Context(), userID, req)
	if err != nil {
		if errors.Is(err, ErrKeyCountLimit) {
			resp.Fail(c, resp.CodeBadRequest, "已达到单用户最多可创建 Key 数")
			return
		}
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, out)
}

// GET /api/keys
func (h *Handler) List(c *gin.Context) {
	userID := middleware.UserID(c)
	if userID == 0 {
		resp.Unauthorized(c, "未登录")
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if size < 1 || size > 100 {
		size = 20
	}
	list, total, err := h.svc.List(c.Request.Context(), userID, (page-1)*size, size)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"list": list, "total": total, "page": page, "page_size": size})
}

// PATCH /api/keys/:id
func (h *Handler) Update(c *gin.Context) {
	userID := middleware.UserID(c)
	if userID == 0 {
		resp.Unauthorized(c, "未登录")
		return
	}
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var req UpdateInput
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest(c, "请求参数错误:"+err.Error())
		return
	}
	k, err := h.svc.Update(c.Request.Context(), userID, id, req)
	if err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, k)
}

// DELETE /api/keys/:id
func (h *Handler) Delete(c *gin.Context) {
	userID := middleware.UserID(c)
	if userID == 0 {
		resp.Unauthorized(c, "未登录")
		return
	}
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if err := h.svc.Delete(c.Request.Context(), userID, id); err != nil {
		resp.InternalErr(c, err)
		return
	}
	resp.OK(c, gin.H{"deleted": id})
}
