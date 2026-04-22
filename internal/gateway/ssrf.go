package gateway

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// ErrForbiddenIP 访问内网/回环/本机元数据地址被 SSRF 防护拦截。
var ErrForbiddenIP = errors.New("gateway: forbidden ip target")

// isForbiddenIP 返回 true 表示 IP 属于"不允许出栈"的段。
// 覆盖:
//   - 未指定地址 0.0.0.0 / ::
//   - 回环 127.0.0.0/8, ::1
//   - 链路本地 169.254.0.0/16(含 169.254.169.254 云元数据),fe80::/10
//   - 私有网络 10/8, 172.16/12, 192.168/16, fc00::/7
//   - 多播 / 广播
func isForbiddenIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	return false
}

// safeDialContext 用于 http.Transport.DialContext。
// 先解析 host,对每个候选 IP 做黑名单校验,通过后再发起 TCP 握手。
// 这样即使 DNS rebinding 在第二次解析时返回不同 IP,也会被这里再次拦截。
var safeDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
	Control:   safeDialControl,
}

func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if isForbiddenIP(ip) {
			return nil, ErrForbiddenIP
		}
	}
	return safeDialer.DialContext(ctx, network, addr)
}

// safeDialControl 在 syscall 层再兜底一次:若 getpeername 拿到的 IP 命中黑名单,
// 直接关闭连接(防御 happy-eyeballs 同时解析 IPv4/IPv6 时的漏网之鱼)。
func safeDialControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip != nil && isForbiddenIP(ip) {
		return ErrForbiddenIP
	}
	return nil
}
