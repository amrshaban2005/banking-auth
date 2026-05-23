package domain

import (
	"strings"

	"github.com/amrshaban2005/banking-auth/logger"
)

const (
	PermissionCustomersReadAll   = "customers:read_all"
	PermissionCustomersReadOne   = "customers:read_one"
	PermissionAccountsCreate     = "accounts:create"
	PermissionTransactionsCreate = "transactions:create"
)

type RolePermissions struct {
	rolePermissions map[string][]string
}

func (r RolePermissions) IsAuthorizedFor(role string, permissionName string) bool {

	for _, r := range r.rolePermissions[role] {
		logger.Info(strings.TrimSpace(permissionName))
		logger.Info(r)
		if r == strings.TrimSpace(permissionName) {
			return true
		}
	}
	return false
}

func GetRolePermissions() RolePermissions {
	return RolePermissions{map[string][]string{
		"admin": {PermissionCustomersReadAll,
			PermissionCustomersReadOne,
			PermissionAccountsCreate,
			PermissionTransactionsCreate},
		"user": {PermissionCustomersReadOne,
			PermissionTransactionsCreate},
	}}

}
