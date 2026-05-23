package domain

import (
	"github.com/amrshaban2005/banking-auth/errs"
	"github.com/amrshaban2005/banking-auth/logger"
	"github.com/dgrijalva/jwt-go"
)

type AuthToken struct {
	token *jwt.Token
}

func (auth AuthToken) NewAccessToken() (string, *errs.AppError) {
	signedString, err := auth.token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("Failed when signing the token " + err.Error())
		return "", errs.NewUnexpectedError("Cannot generate access token")
	}
	return signedString, nil
}

func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token}
}
