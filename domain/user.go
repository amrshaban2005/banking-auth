package domain

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/amrshaban2005/banking-auth/errs"
	"github.com/dgrijalva/jwt-go"
)

type User struct {
	UserName   string
	Role       string
	CustomerId sql.NullString `db:"customer_id"`
	Accounts   sql.NullString `db:"account_numbers"`
}

type AuthRepository interface {
	FindById(ctx context.Context, userName string, password string) (*User, *errs.AppError)
}

func (u User) ClaimsForAccessToken() AccessTokenClaims {
	if u.CustomerId.Valid && u.Accounts.Valid {
		return u.claimsForUser()
	} else {
		return u.claimsForAdmin()
	}
}

func (u User) claimsForUser() AccessTokenClaims {
	accounts := strings.Split(u.Accounts.String, ",")
	return AccessTokenClaims{
		CustomerId: u.CustomerId.String,
		Accounts:   accounts,
		Username:   u.UserName,
		Role:       u.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}

func (u User) claimsForAdmin() AccessTokenClaims {
	return AccessTokenClaims{
		Username: u.UserName,
		Role:     u.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}

}
