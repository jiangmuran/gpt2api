package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ListFilter admin 查询用户列表的过滤条件。
type ListFilter struct {
	Keyword string // 模糊匹配 email/nickname
	Role    string // "" / "user" / "admin"
	Status  string // "" / "active" / "banned"
	GroupID uint64 // 0 表示全部
}

// ListPage admin 分页列出用户。返回结果带最大值兜底,limit 超过 500 强制 500。
func (d *DAO) ListPage(ctx context.Context, f ListFilter, limit, offset int) ([]User, int64, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	where := []string{"deleted_at IS NULL"}
	args := []interface{}{}

	if f.Keyword != "" {
		where = append(where, "(email LIKE ? OR nickname LIKE ?)")
		kw := "%" + f.Keyword + "%"
		args = append(args, kw, kw)
	}
	if f.Role != "" {
		where = append(where, "role = ?")
		args = append(args, f.Role)
	}
	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if f.GroupID > 0 {
		where = append(where, "group_id = ?")
		args = append(args, f.GroupID)
	}

	whereSQL := "WHERE " + strings.Join(where, " AND ")

	var total int64
	if err := d.db.GetContext(ctx, &total,
		`SELECT COUNT(*) FROM users `+whereSQL, args...); err != nil {
		return nil, 0, err
	}

	var items []User
	argsWithLimit := append(args, limit, offset)
	if err := d.db.SelectContext(ctx, &items,
		`SELECT id, email, password_hash, nickname, group_id, role, status,
                credit_balance, credit_frozen, version, last_login_at, last_login_ip,
                created_at, updated_at, deleted_at
           FROM users `+whereSQL+`
          ORDER BY id DESC
          LIMIT ? OFFSET ?`, argsWithLimit...); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// UpdatePatch 用于 admin 更新用户基础字段(允许仅传部分)。
// 注意:不允许通过这个方法改 credit_balance / credit_frozen(走 billing.AdminAdjust)。
type UpdatePatch struct {
	Nickname *string
	Role     *string
	Status   *string
	GroupID  *uint64
}

// Update 执行 UpdatePatch;每个非 nil 字段才会被更新。返回受影响行数。
func (d *DAO) Update(ctx context.Context, id uint64, p UpdatePatch) (int64, error) {
	sets := []string{}
	args := []interface{}{}

	if p.Nickname != nil {
		sets = append(sets, "nickname = ?")
		args = append(args, *p.Nickname)
	}
	if p.Role != nil {
		if *p.Role != "user" && *p.Role != "admin" {
			return 0, fmt.Errorf("invalid role: %s", *p.Role)
		}
		sets = append(sets, "role = ?")
		args = append(args, *p.Role)
	}
	if p.Status != nil {
		if *p.Status != "active" && *p.Status != "banned" {
			return 0, fmt.Errorf("invalid status: %s", *p.Status)
		}
		sets = append(sets, "status = ?")
		args = append(args, *p.Status)
	}
	if p.GroupID != nil {
		sets = append(sets, "group_id = ?")
		args = append(args, *p.GroupID)
	}
	if len(sets) == 0 {
		return 0, nil
	}
	sets = append(sets, "version = version + 1")
	// 若本次 UPDATE 影响到 role/status,一同 bump token_version 让旧 JWT 立即失效。
	if p.Role != nil || p.Status != nil {
		sets = append(sets, "token_version = token_version + 1")
	}
	q := "UPDATE users SET " + strings.Join(sets, ", ") + " WHERE id = ? AND deleted_at IS NULL"
	args = append(args, id)

	res, err := d.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ResetPassword 覆盖 password_hash。hash 由上层用 bcrypt 生成。
// 同时 bump token_version,让该用户所有已签发的 JWT 立即失效。
func (d *DAO) ResetPassword(ctx context.Context, id uint64, hash string) error {
	res, err := d.db.ExecContext(ctx,
		`UPDATE users
            SET password_hash = ?, version = version + 1, token_version = token_version + 1
          WHERE id = ? AND deleted_at IS NULL`, hash, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDelete 将用户标记为删除(并不物理删除,也不回收其 api keys/usage 等)。
// 被删除的用户无法登录,api key 按策略可单独吊销。
// 同时 bump token_version,阻止用户用已有 JWT 继续访问(中间件会拿不到 token_version)。
func (d *DAO) SoftDelete(ctx context.Context, id uint64) error {
	res, err := d.db.ExecContext(ctx,
		`UPDATE users
            SET deleted_at = NOW(), status = 'banned',
                version = version + 1, token_version = token_version + 1
          WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- user_groups CRUD(admin) ----

// ListGroups 列出全部分组(无分页,分组总量很少)。
func (d *DAO) ListGroups(ctx context.Context) ([]Group, error) {
	var out []Group
	err := d.db.SelectContext(ctx, &out,
		`SELECT id, name, ratio, daily_limit_credits, rpm_limit, tpm_limit, remark, created_at, updated_at
           FROM user_groups WHERE deleted_at IS NULL ORDER BY id ASC`)
	return out, err
}

// CreateGroup 插入用户分组,返回自增 id。
func (d *DAO) CreateGroup(ctx context.Context, g *Group) (uint64, error) {
	if g.Name == "" {
		return 0, errors.New("group name required")
	}
	if g.Ratio <= 0 {
		g.Ratio = 1.0
	}
	res, err := d.db.ExecContext(ctx, `
INSERT INTO user_groups (name, ratio, daily_limit_credits, rpm_limit, tpm_limit, remark)
VALUES (?,?,?,?,?,?)`,
		g.Name, g.Ratio, g.DailyLimitCredits, g.RPMLimit, g.TPMLimit, g.Remark)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return uint64(id), nil
}

// UpdateGroup 更新分组字段(全量覆盖);id 不存在返回 ErrNotFound。
func (d *DAO) UpdateGroup(ctx context.Context, g *Group) error {
	res, err := d.db.ExecContext(ctx, `
UPDATE user_groups
   SET name = ?, ratio = ?, daily_limit_credits = ?, rpm_limit = ?, tpm_limit = ?, remark = ?
 WHERE id = ? AND deleted_at IS NULL`,
		g.Name, g.Ratio, g.DailyLimitCredits, g.RPMLimit, g.TPMLimit, g.Remark, g.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteGroup 软删除。调用方应先确保没有用户挂在这个 group 下。
func (d *DAO) DeleteGroup(ctx context.Context, id uint64) error {
	// 禁止删除 id=1(默认 default 分组)
	if id == 1 {
		return errors.New("default group cannot be deleted")
	}
	var used int
	if err := d.db.GetContext(ctx, &used,
		`SELECT COUNT(*) FROM users WHERE group_id = ? AND deleted_at IS NULL`, id); err != nil {
		return err
	}
	if used > 0 {
		return fmt.Errorf("group in use by %d users", used)
	}
	res, err := d.db.ExecContext(ctx,
		`UPDATE user_groups SET deleted_at = NOW() WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- credit_transactions (admin) ----

// CreditLog 用于返回流水列表的简化结构。
type CreditLog struct {
	ID           uint64 `db:"id" json:"id"`
	UserID       uint64 `db:"user_id" json:"user_id"`
	KeyID        uint64 `db:"key_id" json:"key_id"`
	Type         string `db:"type" json:"type"`
	Amount       int64  `db:"amount" json:"amount"`
	BalanceAfter int64  `db:"balance_after" json:"balance_after"`
	RefID        string `db:"ref_id" json:"ref_id"`
	Remark       string `db:"remark" json:"remark"`
	CreatedAt    string `db:"created_at" json:"created_at"`
}

// CreditLogWithUser 全局流水列表的返回结构:带上用户 email/nickname 以便前端展示。
type CreditLogWithUser struct {
	ID           uint64 `db:"id" json:"id"`
	UserID       uint64 `db:"user_id" json:"user_id"`
	UserEmail    string `db:"user_email" json:"user_email"`
	UserNickname string `db:"user_nickname" json:"user_nickname"`
	KeyID        uint64 `db:"key_id" json:"key_id"`
	Type         string `db:"type" json:"type"`
	Amount       int64  `db:"amount" json:"amount"`
	BalanceAfter int64  `db:"balance_after" json:"balance_after"`
	RefID        string `db:"ref_id" json:"ref_id"`
	Remark       string `db:"remark" json:"remark"`
	CreatedAt    string `db:"created_at" json:"created_at"`
}

// CreditLogFilter 全局流水过滤条件。
type CreditLogFilter struct {
	UserID   uint64 // 0=全部
	Keyword  string // 匹配 email/nickname(需 JOIN users)
	Type     string // "" / consume / recharge / refund / redeem / admin_adjust / freeze / unfreeze
	Sign     string // "" / in(>0) / out(<0)
	StartAt  string // "YYYY-MM-DD HH:MM:SS" 或空
	EndAt    string // 同上
}

// ListCreditLogsGlobal 供"积分管理"页面使用:可按用户/关键字/类型/方向/时间过滤。
func (d *DAO) ListCreditLogsGlobal(ctx context.Context, f CreditLogFilter, limit, offset int) ([]CreditLogWithUser, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	where := []string{"1=1"}
	args := []interface{}{}

	if f.UserID > 0 {
		where = append(where, "ct.user_id = ?")
		args = append(args, f.UserID)
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		like := "%" + kw + "%"
		where = append(where, "(u.email LIKE ? OR u.nickname LIKE ?)")
		args = append(args, like, like)
	}
	if t := strings.TrimSpace(f.Type); t != "" {
		where = append(where, "ct.type = ?")
		args = append(args, t)
	}
	switch strings.ToLower(strings.TrimSpace(f.Sign)) {
	case "in":
		where = append(where, "ct.amount > 0")
	case "out":
		where = append(where, "ct.amount < 0")
	}
	if s := strings.TrimSpace(f.StartAt); s != "" {
		where = append(where, "ct.created_at >= ?")
		args = append(args, s)
	}
	if s := strings.TrimSpace(f.EndAt); s != "" {
		where = append(where, "ct.created_at <= ?")
		args = append(args, s)
	}
	ws := strings.Join(where, " AND ")

	var total int64
	if err := d.db.GetContext(ctx, &total, fmt.Sprintf(`
SELECT COUNT(*)
  FROM credit_transactions ct
  LEFT JOIN users u ON u.id = ct.user_id
 WHERE %s`, ws), args...); err != nil {
		return nil, 0, err
	}

	argsPaged := append(args, limit, offset)
	var out []CreditLogWithUser
	err := d.db.SelectContext(ctx, &out, fmt.Sprintf(`
SELECT ct.id, ct.user_id,
       COALESCE(u.email,    '') AS user_email,
       COALESCE(u.nickname, '') AS user_nickname,
       ct.key_id, ct.type, ct.amount, ct.balance_after, ct.ref_id, ct.remark,
       DATE_FORMAT(ct.created_at, '%%Y-%%m-%%d %%H:%%i:%%s') AS created_at
  FROM credit_transactions ct
  LEFT JOIN users u ON u.id = ct.user_id
 WHERE %s
 ORDER BY ct.id DESC
 LIMIT ? OFFSET ?`, ws), argsPaged...)
	return out, total, err
}

// CreditSummary 流水统计摘要。amount 单位:credit·厘。
type CreditSummary struct {
	InToday      int64 `db:"in_today"      json:"in_today"`
	OutToday     int64 `db:"out_today"     json:"out_today"`
	In7Days      int64 `db:"in_7days"      json:"in_7days"`
	Out7Days     int64 `db:"out_7days"     json:"out_7days"`
	InTotal      int64 `db:"in_total"      json:"in_total"`
	OutTotal     int64 `db:"out_total"     json:"out_total"`
	TotalBalance int64 `db:"total_balance" json:"total_balance"`
}

// CreditSummary 聚合:近今日 / 近 7 天 / 累计 入账 + 消耗,以及全站剩余余额。
func (d *DAO) CreditSummary(ctx context.Context) (CreditSummary, error) {
	var s CreditSummary
	err := d.db.GetContext(ctx, &s, `
SELECT
  COALESCE(SUM(CASE WHEN amount > 0 AND DATE(created_at) = CURDATE() THEN amount ELSE 0 END), 0) AS in_today,
  COALESCE(-SUM(CASE WHEN amount < 0 AND DATE(created_at) = CURDATE() THEN amount ELSE 0 END), 0) AS out_today,
  COALESCE(SUM(CASE WHEN amount > 0 AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN amount ELSE 0 END), 0) AS in_7days,
  COALESCE(-SUM(CASE WHEN amount < 0 AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN amount ELSE 0 END), 0) AS out_7days,
  COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) AS in_total,
  COALESCE(-SUM(CASE WHEN amount < 0 THEN amount ELSE 0 END), 0) AS out_total,
  0 AS total_balance
FROM credit_transactions`)
	if err != nil {
		return s, err
	}
	if err := d.db.GetContext(ctx, &s.TotalBalance,
		`SELECT COALESCE(SUM(credit_balance), 0) FROM users WHERE deleted_at IS NULL`); err != nil {
		return s, err
	}
	return s, nil
}

// ListCreditLogs 按 user_id 分页查询流水。actorID=0 查全部。
func (d *DAO) ListCreditLogs(ctx context.Context, userID uint64, limit, offset int) ([]CreditLog, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	args := []interface{}{}
	where := "WHERE 1=1"
	if userID > 0 {
		where += " AND user_id = ?"
		args = append(args, userID)
	}

	var total int64
	if err := d.db.GetContext(ctx, &total,
		`SELECT COUNT(*) FROM credit_transactions `+where, args...); err != nil {
		return nil, 0, err
	}

	argsPaged := append(args, limit, offset)
	var out []CreditLog
	err := d.db.SelectContext(ctx, &out, `
SELECT id, user_id, key_id, type, amount, balance_after, ref_id, remark,
       DATE_FORMAT(created_at,'%Y-%m-%d %H:%i:%s') AS created_at
  FROM credit_transactions `+where+`
 ORDER BY id DESC
 LIMIT ? OFFSET ?`, argsPaged...)
	return out, total, err
}
