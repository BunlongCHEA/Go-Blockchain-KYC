package auth

import (
	"errors"
)

// Role represents a user role
type Role string

const (
	RoleAdmin       Role = "admin"
	RoleBankAdmin   Role = "bank_admin"
	RoleBankOfficer Role = "bank_officer"
	RoleAuditor     Role = "auditor"
	RoleCustomer    Role = "customer"
)

// Permission represents a system permission
type Permission string

const (
	// KYC Permissions
	PermKYCCreate Permission = "kyc:create"
	PermKYCRead   Permission = "kyc:read"
	PermKYCUpdate Permission = "kyc:update"
	PermKYCDelete Permission = "kyc:delete"
	PermKYCVerify Permission = "kyc:verify"
	PermKYCReject Permission = "kyc:reject"

	// Bank Permissions
	PermBankCreate Permission = "bank:create"
	PermBankRead   Permission = "bank:read"
	PermBankUpdate Permission = "bank:update"
	PermBankDelete Permission = "bank:delete"

	// User Permissions
	PermUserCreate Permission = "user:create"
	PermUserRead   Permission = "user:read"
	PermUserUpdate Permission = "user:update"
	PermUserDelete Permission = "user:delete"

	// Blockchain Permissions
	PermBlockchainRead Permission = "blockchain:read"
	PermBlockchainMine Permission = "blockchain:mine"

	// Audit Permissions
	PermAuditRead   Permission = "audit:read"
	PermAuditExport Permission = "audit:export"
)

// RolePermissions defines permissions for each role
var RolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermKYCCreate, PermKYCRead, PermKYCUpdate, PermKYCDelete, PermKYCVerify, PermKYCReject,
		PermBankCreate, PermBankRead, PermBankUpdate, PermBankDelete,
		PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete,
		PermBlockchainRead, PermBlockchainMine,
		PermAuditRead, PermAuditExport,
	},
	RoleBankAdmin: {
		PermKYCCreate, PermKYCRead, PermKYCUpdate, PermKYCVerify, PermKYCReject,
		PermBankRead,
		PermUserCreate, PermUserRead, PermUserUpdate,
		PermBlockchainRead,
		PermAuditRead,
	},
	RoleBankOfficer: {
		PermKYCCreate, PermKYCRead, PermKYCUpdate, PermKYCVerify, PermKYCReject,
		PermBankRead,
		PermBlockchainRead,
	},
	RoleAuditor: {
		PermKYCRead,
		PermBankRead,
		PermUserRead,
		PermBlockchainRead,
		PermAuditRead, PermAuditExport,
	},
	RoleCustomer: {
		PermKYCRead, // Only their own KYC
	},
}

// RBAC handles role-based access control
type RBAC struct {
	rolePermissions map[Role]map[Permission]bool
}

// NewRBAC creates a new RBAC instance
func NewRBAC() *RBAC {
	rbac := &RBAC{
		rolePermissions: make(map[Role]map[Permission]bool),
	}

	// Initialize permission maps
	for role, perms := range RolePermissions {
		rbac.rolePermissions[role] = make(map[Permission]bool)
		for _, perm := range perms {
			rbac.rolePermissions[role][perm] = true
		}
	}

	return rbac
}

// HasPermission checks if a role has a specific permission
func (r *RBAC) HasPermission(role Role, permission Permission) bool {
	perms, exists := r.rolePermissions[role]
	if !exists {
		return false
	}
	return perms[permission]
}

// CheckPermission checks permission and returns an error if denied
func (r *RBAC) CheckPermission(role Role, permission Permission) error {
	if !r.HasPermission(role, permission) {
		return errors.New("permission denied:  " + string(permission))
	}
	return nil
}

// GetRolePermissions returns all permissions for a role
func (r *RBAC) GetRolePermissions(role Role) []Permission {
	return RolePermissions[role]
}

// CanAccessKYC checks if a user can access a specific KYC record
func (r *RBAC) CanAccessKYC(user *User, kycCustomerID string) bool {
	// Admins and auditors can access all KYC records
	if user.Role == RoleAdmin || user.Role == RoleAuditor {
		return true
	}

	// Bank staff can access KYC records for their bank
	if user.Role == RoleBankAdmin || user.Role == RoleBankOfficer {
		return true // In production, check if KYC belongs to their bank
	}

	// Customers can only access their own KYC
	if user.Role == RoleCustomer {
		return user.ID == kycCustomerID
	}

	return false
}

// CanManageBank checks if a user can manage a specific bank
func (r *RBAC) CanManageBank(user *User, bankID string) bool {
	if user.Role == RoleAdmin {
		return true
	}

	if user.Role == RoleBankAdmin && user.BankID == bankID {
		return true
	}

	return false
}

// RequireRole middleware helper - checks if user has required role
func RequireRole(user *User, roles ...Role) error {
	for _, role := range roles {
		if user.Role == role {
			return nil
		}
	}
	return errors.New("insufficient role")
}

// RequirePermission middleware helper - checks if user has required permission
func RequirePermission(rbac *RBAC, user *User, permission Permission) error {
	return rbac.CheckPermission(user.Role, permission)
}
