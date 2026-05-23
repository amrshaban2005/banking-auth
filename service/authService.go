package service

import (
	"context"
	"fmt"

	"github.com/amrshaban2005/banking-auth/domain"
	"github.com/amrshaban2005/banking-auth/dto"
	"github.com/amrshaban2005/banking-auth/errs"
	"github.com/bytedance/gopkg/util/logger"
	"github.com/dgrijalva/jwt-go"
)

type AuthService interface {
	Login(ctx context.Context, login dto.LoginRequest) (dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
}

type DefualtAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func NewAuthService(repo domain.AuthRepository, rolePermissions domain.RolePermissions) DefualtAuthService {
	return DefualtAuthService{repo, rolePermissions}
}

func (a *DefualtAuthService) Login(ctx context.Context, login dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {

	user, err := a.repo.FindById(ctx, login.UserName, login.Password)
	if err != nil {
		return nil, err
	}
	claims := user.ClaimsForAccessToken()
	authToken := domain.NewAuthToken(claims)

	accessToken, err := authToken.NewAccessToken()
	if err != nil {
		return nil, err
	}
	return &dto.LoginResponse{accessToken}, nil
}

func (a *DefualtAuthService) Verify(urlParams map[string]string) *errs.AppError {
	// convert from string to jwt token
	jwtToken, err := jwtTokenFromString(urlParams["token"])
	if err != nil {
		return errs.NewAuthorizationError(err.Error())
	} else {
		// check expiry
		if jwtToken.Valid {
			// type cast the token claims to jwt.MapClaims
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)
			/* if Role if user then check if the account_id and customer_id
			   coming in the URL belongs to the same token
			*/
			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
					return errs.NewAuthorizationError("request not verified with the token claims")
				}
			}
			if !a.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["permissionName"]) {
				return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil

		} else {
			return errs.NewAuthorizationError("Invalid Token")
		}
	}
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}
