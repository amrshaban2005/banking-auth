package domain

import (
	"github.com/amrshaban2005/banking-lib/errs"
	"github.com/amrshaban2005/banking-lib/logger"
	"github.com/dgrijalva/jwt-go"
)

type AuthToken struct {
	token *jwt.Token
}

func (auth AuthToken) NewAccessToken() (string, *errs.AppError) {
	signedString, err := auth.token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("Failed when signing the auth token " + err.Error())
		return "", errs.NewUnexpectedError("Cannot generate access token")
	}
	return signedString, nil
}

func (auth AuthToken) NewRefreshToken() (string, *errs.AppError) {
	claims := auth.token.Claims.(AccessTokenClaims)
	refreshTokenClaims := claims.RefreshTokenClaims()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	signedString, err := token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("Failed when signing the refresh token " + err.Error())
		return "", errs.NewUnexpectedError("Cannot generate refresh token")
	}
	return signedString, nil

}

func NewAccessTokenFromRefreshToken(refreshToken string) (string, *errs.AppError) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		return "", errs.NewAuthenticationError("invalid or expired refresh token")
	}
	refreshClaims := token.Claims.(*RefreshTokenClaims)
	accessTokenClaims := refreshClaims.AccessTokenClaims()
	authToken := NewAuthToken(accessTokenClaims)
	return authToken.NewAccessToken()
}

func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token}
}
