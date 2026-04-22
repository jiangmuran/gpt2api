package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORS 简易跨域中间件。
//
// 安全注意:通配符 "*" 与 Allow-Credentials: true 不能共存(浏览器会拒绝),
// 而代码若同时发这两个头,在部分反向代理 / 旧客户端下可能被利用做跨源凭证窃取。
// 策略:
//   - 白名单为空:不发任何 CORS 头(同源请求仍可用)。
//   - 包含 "*":允许任意 Origin,但此时绝不发 Allow-Credentials。
//     浏览器收到无凭证的通配符头,会自动禁止携带 cookie/Authorization,
//     同时也会禁止读取响应中的敏感头。
//   - 普通白名单:按 Origin 精确匹配,Allow-Credentials: true。
func CORS(origins []string) gin.HandlerFunc {
	allow := make(map[string]struct{}, len(origins))
	allowAll := false
	for _, o := range origins {
		if o == "*" {
			allowAll = true
			continue
		}
		allow[strings.TrimRight(o, "/")] = struct{}{}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			matched := false
			if allowAll {
				c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
				matched = true
			} else if _, ok := allow[strings.TrimRight(origin, "/")]; ok {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Vary", "Origin")
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
				matched = true
			}
			if matched {
				c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-Id")
				c.Writer.Header().Set("Access-Control-Expose-Headers", "X-Request-Id")
				c.Writer.Header().Set("Access-Control-Max-Age", "86400")
			}
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
