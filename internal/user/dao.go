package user

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

// ErrNotFound 表示记录不存在。
var ErrNotFound = errors.New("user: not found")

// DAO 封装 users / user_groups 表访问。
type DAO struct {
	db *sqlx.DB
}

func NewDAO(db *sqlx.DB) *DAO { return &DAO{db: db} }

// ---- user_groups ----

func (d *DAO) GetGroup(ctx context.Context, id uint64) (*Group, error) {
	var g Group
	err := d.db.GetContext(ctx, &g,
		`SELECT id, name, ratio, daily_limit_credits, rpm_limit, tpm_limit, remark, created_at, updated_at
         FROM user_groups WHERE id = ? AND deleted_at IS NULL`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &g, err
}

// ---- users ----

func (d *DAO) GetByID(ctx context.Context, id uint64) (*User, error) {
	var u User
	err := d.db.GetContext(ctx, &u,
		`SELECT * FROM users WHERE id = ? AND deleted_at IS NULL`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (d *DAO) GetByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	err := d.db.GetContext(ctx, &u,
		`SELECT * FROM users WHERE email = ? AND deleted_at IS NULL`, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// Create 插入新用户,返回自增 id。
func (d *DAO) Create(ctx context.Context, u *User) (uint64, error) {
	res, err := d.db.ExecContext(ctx,
		`INSERT INTO users (email, password_hash, nickname, group_id, role, status, credit_balance)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.Email, u.PasswordHash, u.Nickname, u.GroupID, u.Role, u.Status, u.CreditBalance,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return uint64(id), err
}

// UpdateLoginInfo 更新最近登录时间与 IP。
func (d *DAO) UpdateLoginInfo(ctx context.Context, id uint64, ip string) error {
	_, err := d.db.ExecContext(ctx,
		`UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE id = ?`,
		time.Now(), ip, id,
	)
	return err
}

// CountByEmail 用于注册时快速判重。
func (d *DAO) CountByEmail(ctx context.Context, email string) (int, error) {
	var n int
	err := d.db.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM users WHERE email = ? AND deleted_at IS NULL`, email)
	return n, err
}

// CountAll 返回当前有效用户总数(不含软删)。
// 主要用途:"首位注册用户自动成为 admin" 的判定。
func (d *DAO) CountAll(ctx context.Context) (int, error) {
	var n int
	err := d.db.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`)
	return n, err
}

// GetTokenVersion 返回 users.token_version,用于 JWTAuth 中间件比对 claim.tv。
// 未找到 / 已软删的用户返回 ErrNotFound,让中间件拒绝 token。
func (d *DAO) GetTokenVersion(ctx context.Context, id uint64) (uint64, error) {
	var tv uint64
	err := d.db.GetContext(ctx, &tv,
		`SELECT token_version FROM users WHERE id = ? AND deleted_at IS NULL`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return tv, err
}

// BumpTokenVersion 递增指定用户的 token_version,导致其之前签发的所有 JWT 立即失效。
// 调用时机:改密、改 role、改 status、软删。
func (d *DAO) BumpTokenVersion(ctx context.Context, id uint64) error {
	_, err := d.db.ExecContext(ctx,
		`UPDATE users SET token_version = token_version + 1 WHERE id = ?`, id)
	return err
}
