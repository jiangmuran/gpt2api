// Package epay 实现与通用「易支付 / 码支付」类系统的对接协议。
//
// 协议概述(MD5 签名):
//  1. 下单:用户点"充值" -> 后端创建订单 -> 用 GET 参数跳转到 epay.gatewayUrl。
//     下单参数:pid / out_trade_no / notify_url / return_url / name / money / sign / sign_type
//     sign 计算:除 sign/sign_type 外所有非空参数按 key ASCII 升序,拼成 k1=v1&k2=v2...
//     末尾直接拼接 key(注意不再加 &),md5 后转小写。
//  2. 异步通知:POST form(也可能是 GET,按 header Content-Type 判断),
//     校验 sign 同上。trade_status == "TRADE_SUCCESS" 时标记订单已支付。
//  3. 返回文本 "success"(必须原样,不能带换行、HTML),否则上游会无限重试。
//
// 这里刻意不耦合 http handler,由调用方组装 URL / 解析参数,方便单测。
package epay

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Signer 持有商户信息。
type Signer struct {
	PID      string
	Key      string
	SignType string // 目前只支持 MD5
}

func NewSigner(pid, key, signType string) *Signer {
	if signType == "" {
		signType = "MD5"
	}
	return &Signer{PID: pid, Key: key, SignType: signType}
}

// Sign 计算签名。params 不应包含 sign / sign_type 两个字段。
// 为空值会被跳过(和上游习惯保持一致)。
func (s *Signer) Sign(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || k == "sign_type" {
			continue
		}
		if v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	b := strings.Builder{}
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(params[k])
	}
	b.WriteString(s.Key)
	sum := md5.Sum([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Verify 用上游传来的签名和本地 key 重新计算比对。
func (s *Signer) Verify(params map[string]string, got string) bool {
	if got == "" {
		return false
	}
	want := s.Sign(params)
	return strings.EqualFold(want, got)
}

// BuildPayURL 构造跳转给用户浏览器的完整 URL。
// gatewayURL 形如 https://pay.example.com/submit.php
// extra 可以添加自定义字段(如 "type" 指定 alipay|wxpay),为 nil 就让上游收银台显示选择。
func (s *Signer) BuildPayURL(gatewayURL, outTradeNo, name string, priceCNYFen int,
	notifyURL, returnURL string, extra map[string]string,
) (string, error) {
	if gatewayURL == "" {
		return "", errors.New("epay: gateway url empty")
	}
	// money 需要传"元",最多 2 位小数
	money := strconv.FormatFloat(float64(priceCNYFen)/100.0, 'f', 2, 64)

	p := map[string]string{
		"pid":          s.PID,
		"out_trade_no": outTradeNo,
		"name":         name,
		"money":        money,
		"notify_url":   notifyURL,
		"return_url":   returnURL,
		"sign_type":    s.SignType,
	}
	for k, v := range extra {
		if v != "" && k != "sign" && k != "sign_type" {
			p[k] = v
		}
	}
	p["sign"] = s.Sign(p)

	u, err := url.Parse(gatewayURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range p {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// NotifyPayload 抽象一次回调的关键字段。
type NotifyPayload struct {
	OutTradeNo  string            // 商户订单号
	TradeNo     string            // 易支付交易号
	TradeStatus string            // "TRADE_SUCCESS" / 其它
	Name        string
	Money       string // 元(字符串)
	Type        string // alipay / wxpay / ...
	Raw         map[string]string // 原始参数,便于落库排查
}

// ParseNotify 解析回调表单/Query 到 NotifyPayload,并校验签名。
// 签名失败返回 errInvalidSign(调用方打 warn 日志即可)。
var ErrInvalidSign = errors.New("epay: invalid sign")

// ErrPIDMismatch 回调商户号与本地配置不一致。
var ErrPIDMismatch = errors.New("epay: pid mismatch")

func (s *Signer) ParseNotify(form url.Values) (*NotifyPayload, error) {
	params := map[string]string{}
	for k := range form {
		params[k] = form.Get(k)
	}
	// 先校验 pid 再校验签名:pid 不一致说明来源异常,直接拒绝,
	// 不继续暴露 sign 校验细节(避免侧信道)。
	if s.PID != "" && params["pid"] != s.PID {
		return nil, ErrPIDMismatch
	}
	sign := params["sign"]
	if !s.Verify(params, sign) {
		return nil, ErrInvalidSign
	}
	return &NotifyPayload{
		OutTradeNo:  params["out_trade_no"],
		TradeNo:     params["trade_no"],
		TradeStatus: params["trade_status"],
		Name:        params["name"],
		Money:       params["money"],
		Type:        params["type"],
		Raw:         params,
	}, nil
}
