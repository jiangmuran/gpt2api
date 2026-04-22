package account

import (
	"strings"
	"time"
)

// FlexTime 宽松的 time.Time JSON 包装。
// 接收三种输入:
//   - 空串 ""       -> 零值(IsZero()==true)
//   - null          -> 零值
//   - RFC3339 字符串 -> 正常解析
// 为什么需要:前端 date picker 在未选择时往往发 "",原生 time.Time 解析会炸。
type FlexTime struct {
	time.Time
}

func (t *FlexTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// 兼容带毫秒 / 不带时区的常见变体
		if p2, err2 := time.Parse("2006-01-02T15:04:05", s); err2 == nil {
			t.Time = p2
			return nil
		}
		if p3, err3 := time.Parse("2006-01-02 15:04:05", s); err3 == nil {
			t.Time = p3
			return nil
		}
		return err
	}
	t.Time = parsed
	return nil
}

func (t FlexTime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte(`null`), nil
	}
	return []byte(`"` + t.Format(time.RFC3339) + `"`), nil
}
