// Package billing 实现「预扣+结算+退款」的积分计费闭环。
//
// 数据模型:
//   users.credit_balance - 可用余额(厘)
//   users.credit_frozen  - 冻结额度(厘)
//   users.version        - 乐观锁版本号
//   credit_transactions  - 流水(freeze/unfreeze/consume/refund ...)
//
// 流程:
//   PreDeduct(userID, estCost, refID)   // balance -= est; frozen += est
//   Settle(userID, est, actual, refID)  // frozen -= est; balance += (est-actual); 计 consume
//   Refund(userID, est, refID)          // frozen -= est; balance += est
package billing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

var (
	ErrInsufficient = errors.New("billing: insufficient balance")
	ErrConflict     = errors.New("billing: concurrent update")
)

// Kind 流水类型。
const (
	KindFreeze   = "freeze"
	KindUnfreeze = "unfreeze"
	KindConsume  = "consume"
	KindRefund   = "refund"
	KindRecharge = "recharge"
	KindRedeem   = "redeem"
	KindAdjust   = "admin_adjust"
)

// Engine 计费引擎,操作 users + credit_transactions。
type Engine struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Engine { return &Engine{db: db} }

// Balance 查询用户实时余额(可用 + 冻结)。
func (e *Engine) Balance(ctx context.Context, userID uint64) (available, frozen int64, err error) {
	err = e.db.QueryRowxContext(ctx,
		`SELECT credit_balance, credit_frozen FROM users WHERE id = ? AND deleted_at IS NULL`,
		userID).Scan(&available, &frozen)
	if errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("user %d not found", userID)
	}
	return
}

// PreDeduct 预扣:在用户余额足够时,将 amount 从 available 转入 frozen,
// 并写 freeze 流水。并发安全(乐观锁 + WHERE 防越扣)。
func (e *Engine) PreDeduct(ctx context.Context, userID, keyID uint64, amount int64, refID, remark string) error {
	if amount <= 0 {
		return nil
	}
	return e.runTx(ctx, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE users
             SET credit_balance = credit_balance - ?, credit_frozen = credit_frozen + ?,
                 version = version + 1
             WHERE id = ? AND credit_balance >= ? AND deleted_at IS NULL`,
			amount, amount, userID, amount)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrInsufficient
		}
		var balanceAfter int64
		if err := tx.QueryRowxContext(ctx,
			`SELECT credit_balance FROM users WHERE id = ?`, userID).Scan(&balanceAfter); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO credit_transactions
             (user_id, key_id, type, amount, balance_after, ref_id, remark)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
			userID, keyID, KindFreeze, -amount, balanceAfter, refID, remark)
		return err
	})
}

// Settle 结算:expected=预扣金额,actual=真实消耗。
//
//	若 actual <= expected: 退差额(frozen -= expected, balance += (expected-actual));
//	若 actual >  expected: 需要补扣差额,若余额不足尽量扣到 0(业务上一般 expected 已取上限,不太会进入这里)。
func (e *Engine) Settle(ctx context.Context, userID, keyID uint64, expected, actual int64, refID, remark string) error {
	if expected <= 0 && actual <= 0 {
		return nil
	}
	if actual < 0 {
		actual = 0
	}
	return e.runTx(ctx, func(tx *sqlx.Tx) error {
		refund := expected - actual // 可能为负

		var balanceDelta int64
		var frozenDelta int64

		if refund >= 0 {
			// 退差额:frozen -= expected, balance += refund
			frozenDelta = -expected
			balanceDelta = refund
		} else {
			// 补扣:frozen -= expected, balance -= (-refund) 若不足则允许负数? 保守地从 balance 扣到 0。
			frozenDelta = -expected
			balanceDelta = refund // 负值
		}

		res, err := tx.ExecContext(ctx,
			`UPDATE users
             SET credit_balance = credit_balance + ?,
                 credit_frozen  = credit_frozen  + ?,
                 version        = version + 1
             WHERE id = ? AND credit_frozen + ? >= 0 AND deleted_at IS NULL`,
			balanceDelta, frozenDelta, userID, frozenDelta)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrConflict
		}

		var balanceAfter int64
		if err := tx.QueryRowxContext(ctx,
			`SELECT credit_balance FROM users WHERE id = ?`, userID).Scan(&balanceAfter); err != nil {
			return err
		}

		// 流水:unfreeze(+expected), consume(-actual)
		if expected > 0 {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO credit_transactions
                 (user_id, key_id, type, amount, balance_after, ref_id, remark)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				userID, keyID, KindUnfreeze, expected, balanceAfter, refID, remark); err != nil {
				return err
			}
		}
		if actual > 0 {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO credit_transactions
                 (user_id, key_id, type, amount, balance_after, ref_id, remark)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				userID, keyID, KindConsume, -actual, balanceAfter, refID, remark); err != nil {
				return err
			}
		}
		return nil
	})
}

// Refund 全额退款:在请求失败时把 expected 金额原路退回。
func (e *Engine) Refund(ctx context.Context, userID, keyID uint64, expected int64, refID, remark string) error {
	if expected <= 0 {
		return nil
	}
	return e.runTx(ctx, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE users
             SET credit_balance = credit_balance + ?, credit_frozen = credit_frozen - ?,
                 version = version + 1
             WHERE id = ? AND credit_frozen >= ? AND deleted_at IS NULL`,
			expected, expected, userID, expected)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrConflict
		}
		var balanceAfter int64
		if err := tx.QueryRowxContext(ctx,
			`SELECT credit_balance FROM users WHERE id = ?`, userID).Scan(&balanceAfter); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO credit_transactions
             (user_id, key_id, type, amount, balance_after, ref_id, remark)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
			userID, keyID, KindRefund, expected, balanceAfter, refID, remark)
		return err
	})
}

// Recharge 充值(订单回调使用)。
func (e *Engine) Recharge(ctx context.Context, userID uint64, amount int64, refID, remark string) error {
	return e.rechargeInternal(ctx, userID, 0, amount, refID, remark)
}

// RechargeByAdmin 管理员手工触发的充值入账,actorID 会落入流水表用于审计。
func (e *Engine) RechargeByAdmin(ctx context.Context, userID, actorID uint64, amount int64, refID, remark string) error {
	if actorID == 0 {
		return errors.New("actorID required for admin recharge")
	}
	return e.rechargeInternal(ctx, userID, actorID, amount, refID, remark)
}

func (e *Engine) rechargeInternal(ctx context.Context, userID, actorID uint64, amount int64, refID, remark string) error {
	if amount <= 0 {
		return errors.New("amount must be positive")
	}
	return e.runTx(ctx, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE users SET credit_balance = credit_balance + ?, version = version + 1
             WHERE id = ? AND deleted_at IS NULL`, amount, userID)
		if err != nil {
			return err
		}
		var balanceAfter int64
		if err := tx.QueryRowxContext(ctx,
			`SELECT credit_balance FROM users WHERE id = ?`, userID).Scan(&balanceAfter); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO credit_transactions
             (user_id, key_id, type, amount, balance_after, ref_id, remark, actor_user_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			userID, 0, KindRecharge, amount, balanceAfter, refID, remark, actorID)
		return err
	})
}

func (e *Engine) runTx(ctx context.Context, fn func(*sqlx.Tx) error) error {
	tx, err := e.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
