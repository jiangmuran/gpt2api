package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/432539/gpt2api/internal/billing"
	"github.com/432539/gpt2api/internal/settings"
	"github.com/432539/gpt2api/internal/user"
	pkgjwt "github.com/432539/gpt2api/pkg/jwt"
	"github.com/432539/gpt2api/pkg/mailer"
)

// 错误码
var (
	ErrEmailExists       = errors.New("auth: email already exists")
	ErrInvalidCredential = errors.New("auth: invalid email or password")
	ErrUserBanned        = errors.New("auth: user banned")
	ErrRegisterDisabled  = errors.New("auth: user registration is disabled")
	ErrEmailNotAllowed   = errors.New("auth: email domain is not allowed by whitelist")
	ErrPasswordTooShort  = errors.New("auth: password too short")
	ErrLoginRateLimited  = errors.New("auth: too many failed attempts, try again later")
)

// 登录失败计数:按 email 和 IP 分别计数,任一维度命中阈值即锁定窗口。
// 具体参数保守:15 分钟窗口内同一 email 或 IP 连败 10 次即拒绝 15 分钟。
const (
	loginFailWindow   = 15 * time.Minute
	loginFailMaxCount = 10
)

// Service 封装注册、登录、刷新业务。
type Service struct {
	users      *user.DAO
	jwt        *pkgjwt.Manager
	bcryptCost int

	mail    *mailer.Mailer // 可为 nil;为 nil 时不发邮件
	baseURL string

	// 以下两个用于注册开关 / 赠送积分,均为可选依赖。
	// 未注入时:允许注册(兼容旧行为),不发放赠送积分。
	settings *settings.Service
	billing  *billing.Engine

	// rdb 可选:登录失败限流需要 Redis 原子计数。未注入时跳过限流
	// (仍然保留登录逻辑的其它安全性,比如 bcrypt、banned 判断)。
	rdb *redis.Client
}

// NewService 构造认证服务。
// 下限:bcryptCost 必须落在 [bcrypt.MinCost, bcrypt.MaxCost] 区间,
// 且不低于 10(现代安全基线)。越界直接 panic,避免静默降级导致运维以为配置生效。
func NewService(udao *user.DAO, jm *pkgjwt.Manager, bcryptCost int) *Service {
	const minSafeCost = 10
	if bcryptCost < bcrypt.MinCost || bcryptCost > bcrypt.MaxCost {
		panic(fmt.Sprintf("auth: bcrypt_cost %d out of range [%d, %d]",
			bcryptCost, bcrypt.MinCost, bcrypt.MaxCost))
	}
	if bcryptCost < minSafeCost {
		panic(fmt.Sprintf("auth: bcrypt_cost %d below safe minimum %d", bcryptCost, minSafeCost))
	}
	return &Service{users: udao, jwt: jm, bcryptCost: bcryptCost}
}

// SetMailer 把邮件发送器注入进来(可选)。传 nil 或 disabled 的 mailer 即不发邮件。
// 单独出接口,避免 NewService 签名膨胀。
func (s *Service) SetMailer(m *mailer.Mailer, baseURL string) {
	s.mail = m
	s.baseURL = baseURL
}

// SetSettings 注入系统设置服务(用于注册开关 / 默认分组)。
func (s *Service) SetSettings(ss *settings.Service) { s.settings = ss }

// SetBilling 注入计费引擎(用于注册赠送积分)。
func (s *Service) SetBilling(b *billing.Engine) { s.billing = b }

// SetRedis 注入 Redis 客户端;未设置时登录限流会被跳过。
func (s *Service) SetRedis(r *redis.Client) { s.rdb = r }

// Register 新用户注册。
func (s *Service) Register(ctx context.Context, email, password, nickname string) (*user.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return nil, errors.New("email and password required")
	}

	// 动态密码长度阈值(默认 6);>0 才检查,避免 settings 未初始化时把所有注册阻塞
	if s.settings != nil {
		if min := s.settings.PasswordMinLength(); min > 0 && len(password) < min {
			return nil, ErrPasswordTooShort
		}
		// 邮箱域名白名单(空集 = 不限)
		if wl := s.settings.EmailDomainWhitelist(); len(wl) > 0 {
			at := strings.LastIndex(email, "@")
			if at < 0 {
				return nil, ErrEmailNotAllowed
			}
			if _, ok := wl[email[at+1:]]; !ok {
				return nil, ErrEmailNotAllowed
			}
		}
	}

	n, err := s.users.CountByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, ErrEmailExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		return nil, err
	}
	// Bootstrap 规则:若当前系统没有任何用户,首位注册者自动获得 admin 角色。
	// 典型部署场景下一次性生效,后续注册仍为普通用户。
	role := "user"
	total, _ := s.users.CountAll(ctx)
	if total == 0 {
		role = "admin"
	} else if s.settings != nil && !s.settings.AllowRegister() {
		// 已有用户且管理员关闭了开放注册 —— 拒绝。
		return nil, ErrRegisterDisabled
	}

	var groupID uint64 = 1
	if s.settings != nil {
		if g := s.settings.DefaultGroupID(); g > 0 {
			groupID = g
		}
	}

	u := &user.User{
		Email:         email,
		PasswordHash:  string(hash),
		Nickname:      nickname,
		GroupID:       groupID,
		Role:          role,
		Status:        "active",
		CreditBalance: 0,
	}
	id, err := s.users.Create(ctx, u)
	if err != nil {
		return nil, err
	}
	u.ID = id

	// 注册赠送积分(失败不阻断注册流程,仅打日志)
	if s.settings != nil && s.billing != nil {
		if bonus := s.settings.SignupBonusCredits(); bonus > 0 {
			_, _ = s.billing.AdminAdjust(ctx, u.ID, 0, bonus, "signup_bonus", "auto grant on register")
		}
	}

	// 欢迎邮件(可选,失败不影响注册)
	if s.mail != nil && !s.mail.Disabled() {
		subject, html := mailer.RenderWelcome(u.Nickname, u.Email, s.baseURL)
		s.mail.Send(mailer.Message{To: u.Email, Subject: subject, HTML: html})
	}
	return u, nil
}

// Login 校验邮箱密码并签发 token。
// 爆破防护:按 (email, ip) 两个维度分别计数,15 分钟窗口连败 10 次即拒绝后续请求。
// 注入 redis 后启用;未注入时仅做基础校验。
func (s *Service) Login(ctx context.Context, email, password, ip string) (*user.User, *pkgjwt.TokenPair, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if err := s.checkLoginRate(ctx, email, ip); err != nil {
		return nil, nil, err
	}
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			s.bumpLoginFail(ctx, email, ip)
			return nil, nil, ErrInvalidCredential
		}
		return nil, nil, err
	}
	if u.Status == "banned" {
		return nil, nil, ErrUserBanned
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		s.bumpLoginFail(ctx, email, ip)
		return nil, nil, ErrInvalidCredential
	}
	// 登录成功:清零失败计数,避免误锁合法用户。
	s.resetLoginFail(ctx, email, ip)
	pair, err := s.jwt.Issue(u.ID, u.Role, u.TokenVersion)
	if err != nil {
		return nil, nil, err
	}
	_ = s.users.UpdateLoginInfo(ctx, u.ID, ip)
	return u, pair, nil
}

// ---- 登录限流辅助 ----

func loginFailKey(dim, val string) string {
	return "auth:login_fail:" + dim + ":" + val
}

func (s *Service) checkLoginRate(ctx context.Context, email, ip string) error {
	if s.rdb == nil {
		return nil
	}
	for _, k := range []string{loginFailKey("email", email), loginFailKey("ip", ip)} {
		n, err := s.rdb.Get(ctx, k).Int64()
		if err == redis.Nil || err != nil {
			continue
		}
		if n >= loginFailMaxCount {
			return ErrLoginRateLimited
		}
	}
	return nil
}

func (s *Service) bumpLoginFail(ctx context.Context, email, ip string) {
	if s.rdb == nil {
		return
	}
	for _, k := range []string{loginFailKey("email", email), loginFailKey("ip", ip)} {
		if k == loginFailKey("ip", "") {
			continue
		}
		// pipeline: INCR + EXPIRE(仅第一次写入时设置过期),简化为每次都刷 TTL。
		_ = s.rdb.Incr(ctx, k).Err()
		_ = s.rdb.Expire(ctx, k, loginFailWindow).Err()
	}
}

func (s *Service) resetLoginFail(ctx context.Context, email, ip string) {
	if s.rdb == nil {
		return
	}
	_ = s.rdb.Del(ctx,
		loginFailKey("email", email),
		loginFailKey("ip", ip)).Err()
}

// HashPassword 对外暴露 bcrypt 哈希(cost 由 service 持有),admin 重置密码走这里。
func (s *Service) HashPassword(plain string) (string, error) {
	if len(plain) < 6 {
		return "", errors.New("password too short")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), s.bcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// VerifyPassword 校验指定 user 的明文密码是否正确(不签发 token)。
// 主要用于"高危操作二次确认"场景(如恢复数据库、调整积分)。
// 正确返回 nil;错误返回 ErrInvalidCredential / ErrUserBanned 等。
func (s *Service) VerifyPassword(ctx context.Context, userID uint64, password string) error {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return ErrInvalidCredential
		}
		return err
	}
	if u.Status == "banned" {
		return ErrUserBanned
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return ErrInvalidCredential
	}
	return nil
}

// Refresh 用 refresh_token 换新的 access_token 对。
// token_version 不匹配当前用户值时拒绝(密码改过 / 被强制下线)。
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*pkgjwt.TokenPair, error) {
	claims, err := s.jwt.VerifyRefresh(refreshToken)
	if err != nil {
		return nil, err
	}
	u, err := s.users.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}
	if u.Status == "banned" {
		return nil, ErrUserBanned
	}
	if claims.TokenVersion != u.TokenVersion {
		return nil, ErrInvalidCredential
	}
	return s.jwt.Issue(u.ID, u.Role, u.TokenVersion)
}
