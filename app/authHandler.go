package app

import (
	"net/http"

	"github.com/amrshaban2005/banking-auth/dto"
	"github.com/amrshaban2005/banking-auth/logger"
	"github.com/amrshaban2005/banking-auth/service"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	service service.DefualtAuthService
}

func (a AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error("Error while read login params " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid data"})
		return
	}

	response, err := a.service.Login(c.Request.Context(), req)
	if err != nil {
		c.JSON(err.Code, gin.H{"error": err.AsMessage()})
		return
	}
	c.JSON(http.StatusOK, response.AccessToken)
}

/*
	Sample URL string

http://localhost:8181/auth/verify?token=somevalidtokenstring&permissionName=GetCustomer&customer_id=2000&account_id=95470
*/
func (a AuthHandler) Verify(c *gin.Context) {
	urlParams := make(map[string]string)

	for key, values := range c.Request.URL.Query() {
		urlParams[key] = values[0]
	}

	if urlParams["token"] != "" {
		err := a.service.Verify(urlParams)
		// verify from service
		if err != nil {
			c.JSON(err.Code, notAuthorizedReponse(err.Message))
			return
		} else {
			c.JSON(http.StatusOK, authorizedReponse())
		}
	} else {
		c.JSON(http.StatusForbidden, notAuthorizedReponse("Missing token"))
	}

}

func notAuthorizedReponse(message string) gin.H {
	return gin.H{
		"isAuthorized": false,
		"message":      message,
	}
}

func authorizedReponse() gin.H {
	return gin.H{
		"isAuthorized": true,
	}
}
