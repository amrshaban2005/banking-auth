# banking-auth

Authentication service for the banking platform. Handles user login, JWT verification with role-based permissions, and access-token refresh.

## Stack

- Go + [Gin](https://github.com/gin-gonic/gin)
- PostgreSQL via [pgx](https://github.com/jackc/pgx)
- JWT ([dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go))

## Prerequisites

- Go 1.26+
- PostgreSQL with the auth schema and user data populated

## Configuration

Set the following environment variables before starting the service:

| Variable | Description |
|----------|-------------|
| `SERVER_ADDRESS` | Host the HTTP server binds to |
| `SERVER_PORT` | Port the HTTP server listens on |
| `DB_USER` | PostgreSQL username |
| `DB_PASSWD` | PostgreSQL password |
| `DB_ADDR` | PostgreSQL host |
| `DB_PORT` | PostgreSQL port |
| `DB_NAME` | PostgreSQL database name |

## Run

```bash
go run main.go
```

Or use the helper script after setting your own environment values:

```bash
./start.sh
```

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/login` | Authenticate with credentials; returns access and refresh tokens |
| `GET` | `/auth/verify` | Validate a token and check permission (query params: `token`, `permissionName`, and optionally `customer_id`, `account_id`) |
| `GET` | `/auth/refresh` | Issue a new access token using an expired access token and a valid refresh token |

### Login request body

```json
{
  "user_name": "<username>",
  "password": "<password>"
}
```

### Refresh request body

```json
{
  "access_token": "<expired access token>",
  "refresh_token": "<refresh token>"
}
```

## Roles & permissions

- **admin** — full access to customer, account, and transaction operations
- **user** — scoped access; token claims are checked against `customer_id` and `account_id` on verify
