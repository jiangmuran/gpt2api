package billing

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// 调账硬限额 — 防止被劫持的管理员账号一次性加/扣巨额积分套现。
// 上限单位是 credit(厘),AdminAdjustMaxDelta 相当于单次最多 ±10,000,000 分(10 万元),
// 实际生产环境可按业务调低。AdminAdjustRateWindow 与 AdminAdjustRateLimit
// 配合 Redis 外部计数器(调用方实现)或 DB 窗口查询做速率限制。
const (
	AdminAdjustMaxDelta      = int64(1_000_000_000) // 单次 |delta| 上限(credit·厘)
	AdminAdjustDailyMaxTotal = int64(5_000_000_000) // 单个管理员 24h 内累计 |delta| 上限
)

// ErrAdjustExceedsLimit 单笔 |delta| 超过硬上限。
var ErrAdjustExceedsLimit = errors.New("billing: adjust amount exceeds per-operation limit")

// ErrAdjustDailyExceeded 当前管理员 24h 内的累计调账超过 AdminAdjustDailyMaxTotal。
var ErrAdjustDailyExceeded = errors.New("billing: admin daily adjust limit exceeded")

// AdminAdjust 管理员手工调账。
//
//	delta > 0  加积分(例如补偿/赠送)
//	delta < 0  扣积分(例如反作弊回收),允许把余额扣到 >=0(扣到负数会返回错误)
//
// 同时写一条 type=admin_adjust 的流水,ref_id 建议填 admin 的 user_id 字符串,
// remark 由调用方传入人类可读原因。actorID 是发起者 user_id,仅写入 remark 前缀,
// 方便审计时快速定位。
//
// 幂等性:调用方需自己保证(比如前端按钮 debounce);
// 服务端只做原子执行,不去重。
//
// 限额:单次 |delta| 不得超过 AdminAdjustMaxDelta;更细粒度的"日累计 / 频率"
// 限制由调用侧(handler)基于 Redis 令牌桶实现,避免锁住核心事务。
func (e *Engine) AdminAdjust(ctx context.Context, targetUserID, actorID uint64, delta int64, refID, remark string) (balanceAfter int64, err error) {
	if delta == 0 {
		return 0, errors.New("delta must not be zero")
	}
	mag := delta
	if mag < 0 {
		mag = -mag
	}
	if mag > AdminAdjustMaxDelta {
		return 0, ErrAdjustExceedsLimit
	}
	// 24h 累计上限(含本次)。actorID=0 属于系统/注册赠送路径,不纳入管理员限额。
	if actorID > 0 {
		var used int64
		if err = e.db.GetContext(ctx, &used, `
SELECT COALESCE(SUM(ABS(amount)), 0)
  FROM credit_transactions
 WHERE actor_user_id = ?
   AND type = ?
   AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)`, actorID, KindAdjust); err != nil {
			return 0, err
		}
		if used+mag > AdminAdjustDailyMaxTotal {
			return 0, ErrAdjustDailyExceeded
		}
	}
	err = e.runTx(ctx, func(tx *sqlx.Tx) error {
		// 扣款时 WHERE 子句保证不会扣成负数
		var res sqlResult
		if delta > 0 {
			res, err = execR(tx, ctx,
				`UPDATE users
                    SET credit_balance = credit_balance + ?, version = version + 1
                  WHERE id = ? AND deleted_at IS NULL`, delta, targetUserID)
		} else {
			neg := -delta
			res, err = execR(tx, ctx,
				`UPDATE users
                    SET credit_balance = credit_balance - ?, version = version + 1
                  WHERE id = ? AND credit_balance >= ? AND deleted_at IS NULL`,
				neg, targetUserID, neg)
		}
		if err != nil {
			return err
		}
		if res.RowsAffected == 0 {
			if delta < 0 {
				return ErrInsufficient
			}
			return fmt.Errorf("user %d not found", targetUserID)
		}
		if err := tx.QueryRowxContext(ctx,
			`SELECT credit_balance FROM users WHERE id = ?`, targetUserID).Scan(&balanceAfter); err != nil {
			return err
		}
		fullRemark := remark
		if actorID > 0 {
			fullRemark = fmt.Sprintf("[by admin=%d] %s", actorID, remark)
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO credit_transactions
              (user_id, key_id, type, amount, balance_after, ref_id, remark, actor_user_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			targetUserID, 0, KindAdjust, delta, balanceAfter, refID, fullRemark, actorID)
		return err
	})
	return
}

// sqlResult 对 sql.Result 的简化,只保留 RowsAffected,避免在 runTx 里多次判断错误。
type sqlResult struct {
	RowsAffected int64
}

func execR(tx *sqlx.Tx, ctx context.Context, q string, args ...interface{}) (sqlResult, error) {
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return sqlResult{}, err
	}
	n, _ := res.RowsAffected()
	return sqlResult{RowsAffected: n}, nil
}
