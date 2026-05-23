package domain

import (
	"context"
	"errors"

	"github.com/amrshaban2005/banking-auth/errs"
	"github.com/amrshaban2005/banking-auth/logger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuthRepositoryDB struct {
	pool *pgxpool.Pool
}

func NewAuthRepositoryDB(pool *pgxpool.Pool) AuthRepositoryDB {
	return AuthRepositoryDB{pool}
}

func (a AuthRepositoryDB) FindById(ctx context.Context, userName string, password string) (*User, *errs.AppError) {
	sqlSelect := `SELECT username, role, u.customer_id, STRING_AGG(a.account_id::text, ',') as account_numbers
 				  FROM users	u  Left Join accounts a on u.customer_id = a.customer_id
	              WHERE username=$1 AND password=$2
				  Group by username,password,role,u.customer_id`

	rows, err := a.pool.Query(ctx, sqlSelect, userName, password)

	if err != nil {
		logger.Error("error while fetching user by id " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	defer rows.Close()

	user, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[User])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.NewNotFoundError("User not found")
		}
		logger.Error("error while mapping user record " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	return &user, nil

}
