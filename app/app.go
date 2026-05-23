package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/amrshaban2005/banking-auth/domain"
	"github.com/amrshaban2005/banking-auth/logger"
	"github.com/amrshaban2005/banking-auth/service"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func sanityCheck() {
	envProps := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
		"DB_USER",
		"DB_ADDR",
		"DB_PORT",
		"DB_NAME",
	}

	for _, k := range envProps {
		if os.Getenv(k) == "" {
			logger.Fatal(fmt.Sprintf("Enviroment variable %s not provided ", k))
		}
	}
}

func Start() {
	sanityCheck()

	router := gin.Default()

	pool := getDBClient()

	authRepositoryDB := domain.NewAuthRepositoryDB(pool)
	rolePermissions := domain.GetRolePermissions()

	ah := &AuthHandler{service.NewAuthService(authRepositoryDB, rolePermissions)}

	router.GET("auth/login", ah.Login)
	router.GET("auth/verify", ah.Verify)

	// starting the server
	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")

	logger.Info(fmt.Sprintf("Starting server on:%s:%s", address, port))

	log.Fatal(router.Run(fmt.Sprintf("%s:%s", address, port)))
}

func getDBClient() *pgxpool.Pool {
	dbUser := os.Getenv("DB_USER")
	dbPasswd := os.Getenv("DB_PASSWD")
	dbAddr := os.Getenv("DB_ADDR")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", dbUser, dbPasswd, dbAddr, dbPort, dbName)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		panic(err)
	}

	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		panic(err)
	}
	return pool

}
