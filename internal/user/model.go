package user

import (
	"database/sql"
	"time"
)

// User 对应 users 表。
type User struct {
	ID            uint64       `db:"id" json:"id"`
	Email         string       `db:"email" json:"email"`
	PasswordHash  string       `db:"password_hash" json:"-"`
	Nickname      string       `db:"nickname" json:"nickname"`
	GroupID       uint64       `db:"group_id" json:"group_id"`
	Role          string       `db:"role" json:"role"`
	Status        string       `db:"status" json:"status"`
	CreditBalance int64        `db:"credit_balance" json:"credit_balance"`
	CreditFrozen  int64        `db:"credit_frozen" json:"credit_frozen"`
	Version       uint64       `db:"version" json:"-"`
	TokenVersion  uint64       `db:"token_version" json:"-"`
	LastLoginAt   sql.NullTime `db:"last_login_at" json:"last_login_at,omitempty"`
	LastLoginIP   string       `db:"last_login_ip" json:"last_login_ip,omitempty"`
	CreatedAt     time.Time    `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time    `db:"updated_at" json:"updated_at"`
	DeletedAt     sql.NullTime `db:"deleted_at" json:"-"`
}

// Group 对应 user_groups 表。
type Group struct {
	ID                 uint64    `db:"id" json:"id"`
	Name               string    `db:"name" json:"name"`
	Ratio              float64   `db:"ratio" json:"ratio"`
	DailyLimitCredits  int64     `db:"daily_limit_credits" json:"daily_limit_credits"`
	RPMLimit           int       `db:"rpm_limit" json:"rpm_limit"`
	TPMLimit           int64     `db:"tpm_limit" json:"tpm_limit"`
	Remark             string    `db:"remark" json:"remark"`
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
	UpdatedAt          time.Time `db:"updated_at" json:"updated_at"`
}
