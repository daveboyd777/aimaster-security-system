# AIMaster Authentication and Authorization Framework
# Provides comprehensive user authentication, role-based access control, and session management

#Requires -Version 7.0
#Requires -Module Microsoft.PowerShell.SecretManagement

using namespace System.Security.Cryptography
using namespace System.Security.Principal
using namespace System.IdentityModel.Tokens.Jwt
using namespace System.Text

[CmdletBinding()]
param()

# Import required modules
Import-Module -Name (Join-Path $PSScriptRoot "../Config/SecurityConfiguration.psm1") -Force

# User and role classes
class AIMasterUser {
    [string]$UserId
    [string]$Username
    [string]$Email
    [string]$PasswordHash
    [string]$Salt
    [string[]]$Roles
    [hashtable]$Attributes
    [datetime]$CreatedAt
    [datetime]$LastLoginAt
    [datetime]$LastPasswordChange
    [bool]$IsActive
    [bool]$IsLocked
    [int]$FailedLoginAttempts
    [datetime]$LockoutExpiry
    
    AIMasterUser([string]$username, [string]$email) {
        $this.UserId = [System.Guid]::NewGuid().ToString()
        $this.Username = $username
        $this.Email = $email
        $this.Roles = @()
        $this.Attributes = @{}
        $this.CreatedAt = Get-Date
        $this.LastPasswordChange = Get-Date
        $this.IsActive = $true
        $this.IsLocked = $false
        $this.FailedLoginAttempts = 0
        $this.LockoutExpiry = [datetime]::MinValue
    }
    
    [void] SetPassword([string]$password, [hashtable]$complexity = @{}) {
        # Validate password complexity
        if (-not $this.ValidatePasswordComplexity($password, $complexity)) {
            throw "Password does not meet complexity requirements"
        }
        
        # Generate salt and hash password
        $this.Salt = [System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        $this.PasswordHash = $this.HashPassword($password, $this.Salt)
        $this.LastPasswordChange = Get-Date
    }
    
    [bool] ValidatePassword([string]$password) {
        $hash = $this.HashPassword($password, $this.Salt)
        return $hash -eq $this.PasswordHash
    }
    
    [string] HashPassword([string]$password, [string]$salt) {
        $saltBytes = [System.Convert]::FromBase64String($salt)
        $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($password)
        
        # Use PBKDF2 with SHA-256
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passwordBytes, $saltBytes, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $hashBytes = $pbkdf2.GetBytes(32)
        
        return [System.Convert]::ToBase64String($hashBytes)
    }
    
    [bool] ValidatePasswordComplexity([string]$password, [hashtable]$requirements) {
        if ($requirements.Count -eq 0) {
            # Default requirements
            $requirements = @{
                MinLength = 12
                RequireUppercase = $true
                RequireLowercase = $true
                RequireNumbers = $true
                RequireSpecialChars = $true
            }
        }
        
        # Check length
        if ($password.Length -lt $requirements.MinLength) {
            return $false
        }
        
        # Check character requirements
        if ($requirements.RequireUppercase -and $password -cnotmatch "[A-Z]") {
            return $false
        }
        
        if ($requirements.RequireLowercase -and $password -cnotmatch "[a-z]") {
            return $false
        }
        
        if ($requirements.RequireNumbers -and $password -notmatch "\d") {
            return $false
        }
        
        if ($requirements.RequireSpecialChars -and $password -notmatch "[!@#$%^&*(),.?\":{}|<>]") {
            return $false
        }
        
        return $true
    }
    
    [void] AddRole([string]$role) {
        if ($this.Roles -notcontains $role) {
            $this.Roles += $role
        }
    }
    
    [void] RemoveRole([string]$role) {
        $this.Roles = $this.Roles | Where-Object { $_ -ne $role }
    }
    
    [bool] HasRole([string]$role) {
        return $this.Roles -contains $role
    }
    
    [bool] HasAnyRole([string[]]$roles) {
        foreach ($role in $roles) {
            if ($this.HasRole($role)) {
                return $true
            }
        }
        return $false
    }
    
    [void] LockAccount([int]$durationMinutes = 30) {
        $this.IsLocked = $true
        $this.LockoutExpiry = (Get-Date).AddMinutes($durationMinutes)
    }
    
    [void] UnlockAccount() {
        $this.IsLocked = $false
        $this.FailedLoginAttempts = 0
        $this.LockoutExpiry = [datetime]::MinValue
    }
    
    [bool] IsAccountLocked() {
        if (-not $this.IsLocked) {
            return $false
        }
        
        if ($this.LockoutExpiry -lt (Get-Date)) {
            $this.UnlockAccount()
            return $false
        }
        
        return $true
    }
    
    [hashtable] ToHashtable() {
        return @{
            UserId = $this.UserId
            Username = $this.Username
            Email = $this.Email
            Roles = $this.Roles
            Attributes = $this.Attributes
            CreatedAt = $this.CreatedAt
            LastLoginAt = $this.LastLoginAt
            IsActive = $this.IsActive
            IsLocked = $this.IsLocked
            FailedLoginAttempts = $this.FailedLoginAttempts
        }
    }
}

class AIMasterRole {
    [string]$RoleId
    [string]$RoleName
    [string]$Description
    [string[]]$Permissions
    [hashtable]$Attributes
    [datetime]$CreatedAt
    
    AIMasterRole([string]$roleName, [string]$description = "") {
        $this.RoleId = [System.Guid]::NewGuid().ToString()
        $this.RoleName = $roleName
        $this.Description = $description
        $this.Permissions = @()
        $this.Attributes = @{}
        $this.CreatedAt = Get-Date
    }
    
    [void] AddPermission([string]$permission) {
        if ($this.Permissions -notcontains $permission) {
            $this.Permissions += $permission
        }
    }
    
    [void] RemovePermission([string]$permission) {
        $this.Permissions = $this.Permissions | Where-Object { $_ -ne $permission }
    }
    
    [bool] HasPermission([string]$permission) {
        return $this.Permissions -contains $permission -or $this.Permissions -contains "*"
    }
    
    [hashtable] ToHashtable() {
        return @{
            RoleId = $this.RoleId
            RoleName = $this.RoleName
            Description = $this.Description
            Permissions = $this.Permissions
            Attributes = $this.Attributes
            CreatedAt = $this.CreatedAt
        }
    }
}

class AuthenticationToken {
    [string]$TokenId
    [string]$UserId
    [string]$TokenType
    [datetime]$IssuedAt
    [datetime]$ExpiresAt
    [hashtable]$Claims
    [string]$Signature
    [bool]$IsRevoked
    
    AuthenticationToken([string]$userId, [string]$tokenType, [int]$expirationMinutes = 60) {
        $this.TokenId = [System.Guid]::NewGuid().ToString()
        $this.UserId = $userId
        $this.TokenType = $tokenType
        $this.IssuedAt = Get-Date
        $this.ExpiresAt = (Get-Date).AddMinutes($expirationMinutes)
        $this.Claims = @{}
        $this.IsRevoked = $false
        $this.GenerateSignature()
    }
    
    [void] GenerateSignature() {
        $payload = "$($this.TokenId):$($this.UserId):$($this.IssuedAt):$($this.ExpiresAt)"
        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        
        # Use HMAC-SHA256 for signature
        $key = [System.Text.Encoding]::UTF8.GetBytes("AIMaster-Secret-Key-Change-In-Production")
        $hmac = New-Object System.Security.Cryptography.HMACSHA256($key)
        $hashBytes = $hmac.ComputeHash($payloadBytes)
        $this.Signature = [System.Convert]::ToBase64String($hashBytes)
    }
    
    [bool] ValidateSignature() {
        $payload = "$($this.TokenId):$($this.UserId):$($this.IssuedAt):$($this.ExpiresAt)"
        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        
        $key = [System.Text.Encoding]::UTF8.GetBytes("AIMaster-Secret-Key-Change-In-Production")
        $hmac = New-Object System.Security.Cryptography.HMACSHA256($key)
        $hashBytes = $hmac.ComputeHash($payloadBytes)
        $expectedSignature = [System.Convert]::ToBase64String($hashBytes)
        
        return $this.Signature -eq $expectedSignature
    }
    
    [bool] IsValid() {
        if ($this.IsRevoked) {
            return $false
        }
        
        if ($this.ExpiresAt -lt (Get-Date)) {
            return $false
        }
        
        return $this.ValidateSignature()
    }
    
    [void] Revoke() {
        $this.IsRevoked = $true
    }
    
    [hashtable] ToHashtable() {
        return @{
            TokenId = $this.TokenId
            UserId = $this.UserId
            TokenType = $this.TokenType
            IssuedAt = $this.IssuedAt
            ExpiresAt = $this.ExpiresAt
            Claims = $this.Claims
            IsRevoked = $this.IsRevoked
        }
    }
}

# Main authentication manager class
class AuthenticationManager {
    [SecurityManager]$SecurityManager
    [hashtable]$Users = @{}
    [hashtable]$Roles = @{}
    [hashtable]$ActiveTokens = @{}
    [hashtable]$AuthenticationProviders = @{}
    [int]$MaxFailedAttempts = 5
    [int]$LockoutDurationMinutes = 30
    [int]$TokenExpirationMinutes = 60
    [bool]$RequireMFA = $false
    
    AuthenticationManager([SecurityManager]$securityManager) {
        $this.SecurityManager = $securityManager
        $this.InitializeDefaultRoles()
        $this.LoadUsers()
        $this.LoadRoles()
        
        $this.SecurityManager.LogSecurityEvent("AuthenticationManager initialized", "Information")
    }
    
    [void] InitializeDefaultRoles() {
        # Admin role - full system access
        $adminRole = [AIMasterRole]::new("Administrator", "Full system administrator access")
        $adminRole.AddPermission("*")  # Wildcard for all permissions
        $this.Roles[$adminRole.RoleId] = $adminRole
        
        # User role - basic system access
        $userRole = [AIMasterRole]::new("User", "Standard user access")
        $userRole.AddPermission("sandbox.create")
        $userRole.AddPermission("sandbox.execute")
        $userRole.AddPermission("sandbox.view")
        $this.Roles[$userRole.RoleId] = $userRole
        
        # Developer role - development environment access
        $developerRole = [AIMasterRole]::new("Developer", "Developer environment access")
        $developerRole.AddPermission("sandbox.create")
        $developerRole.AddPermission("sandbox.execute")
        $developerRole.AddPermission("sandbox.view")
        $developerRole.AddPermission("sandbox.debug")
        $developerRole.AddPermission("deployment.development")
        $this.Roles[$developerRole.RoleId] = $developerRole
        
        # Auditor role - read-only access
        $auditorRole = [AIMasterRole]::new("Auditor", "Read-only access for auditing")
        $auditorRole.AddPermission("*.read")
        $auditorRole.AddPermission("audit.view")
        $auditorRole.AddPermission("logs.view")
        $this.Roles[$auditorRole.RoleId] = $auditorRole
        
        $this.SecurityManager.LogSecurityEvent("Default roles initialized", "Information")
    }
    
    [void] LoadUsers() {
        try {
            $userStorePath = Join-Path $this.SecurityManager.Config.GetSecureRoot() "Config/users.json"
            if (Test-Path $userStorePath) {
                $userData = Get-Content $userStorePath | ConvertFrom-Json
                foreach ($user in $userData) {
                    $userObj = [AIMasterUser]::new($user.Username, $user.Email)
                    $userObj.UserId = $user.UserId
                    $userObj.PasswordHash = $user.PasswordHash
                    $userObj.Salt = $user.Salt
                    $userObj.Roles = $user.Roles
                    $userObj.Attributes = $user.Attributes
                    $userObj.CreatedAt = [datetime]$user.CreatedAt
                    $userObj.LastLoginAt = [datetime]$user.LastLoginAt
                    $userObj.LastPasswordChange = [datetime]$user.LastPasswordChange
                    $userObj.IsActive = $user.IsActive
                    $userObj.IsLocked = $user.IsLocked
                    $userObj.FailedLoginAttempts = $user.FailedLoginAttempts
                    
                    $this.Users[$userObj.UserId] = $userObj
                }
                $this.SecurityManager.LogSecurityEvent("Users loaded from storage", "Information")
            }
        } catch {
            $this.SecurityManager.LogSecurityEvent("Failed to load users: $($_.Exception.Message)", "Warning")
        }
    }
    
    [void] LoadRoles() {
        try {
            $roleStorePath = Join-Path $this.SecurityManager.Config.GetSecureRoot() "Config/roles.json"
            if (Test-Path $roleStorePath) {
                $roleData = Get-Content $roleStorePath | ConvertFrom-Json
                foreach ($role in $roleData) {
                    if (-not $this.Roles.ContainsKey($role.RoleId)) {
                        $roleObj = [AIMasterRole]::new($role.RoleName, $role.Description)
                        $roleObj.RoleId = $role.RoleId
                        $roleObj.Permissions = $role.Permissions
                        $roleObj.Attributes = $role.Attributes
                        $roleObj.CreatedAt = [datetime]$role.CreatedAt
                        
                        $this.Roles[$roleObj.RoleId] = $roleObj
                    }
                }
                $this.SecurityManager.LogSecurityEvent("Custom roles loaded from storage", "Information")
            }
        } catch {
            $this.SecurityManager.LogSecurityEvent("Failed to load roles: $($_.Exception.Message)", "Warning")
        }
    }
    
    [void] SaveUsers() {
        try {
            $userStorePath = Join-Path $this.SecurityManager.Config.GetSecureRoot() "Config/users.json"
            $userData = @()
            foreach ($user in $this.Users.Values) {
                $userData += @{
                    UserId = $user.UserId
                    Username = $user.Username
                    Email = $user.Email
                    PasswordHash = $user.PasswordHash
                    Salt = $user.Salt
                    Roles = $user.Roles
                    Attributes = $user.Attributes
                    CreatedAt = $user.CreatedAt
                    LastLoginAt = $user.LastLoginAt
                    LastPasswordChange = $user.LastPasswordChange
                    IsActive = $user.IsActive
                    IsLocked = $user.IsLocked
                    FailedLoginAttempts = $user.FailedLoginAttempts
                }
            }
            
            $userData | ConvertTo-Json -Depth 5 | Set-Content $userStorePath -Force
            $this.SecurityManager.LogSecurityEvent("Users saved to storage", "Information")
        } catch {
            $this.SecurityManager.LogSecurityEvent("Failed to save users: $($_.Exception.Message)", "Error")
        }
    }
    
    [void] SaveRoles() {
        try {
            $roleStorePath = Join-Path $this.SecurityManager.Config.GetSecureRoot() "Config/roles.json"
            $roleData = @()
            foreach ($role in $this.Roles.Values) {
                $roleData += $role.ToHashtable()
            }
            
            $roleData | ConvertTo-Json -Depth 5 | Set-Content $roleStorePath -Force
            $this.SecurityManager.LogSecurityEvent("Roles saved to storage", "Information")
        } catch {
            $this.SecurityManager.LogSecurityEvent("Failed to save roles: $($_.Exception.Message)", "Error")
        }
    }
    
    [AIMasterUser] CreateUser([string]$username, [string]$email, [string]$password, [string[]]$roles = @()) {
        try {
            # Check if user already exists
            $existingUser = $this.Users.Values | Where-Object { $_.Username -eq $username -or $_.Email -eq $email }
            if ($existingUser) {
                throw "User with username '$username' or email '$email' already exists"
            }
            
            # Create new user
            $user = [AIMasterUser]::new($username, $email)
            $user.SetPassword($password, $this.SecurityManager.Config.AccessControls.PasswordComplexity)
            
            # Assign roles
            foreach ($roleName in $roles) {
                $role = $this.Roles.Values | Where-Object { $_.RoleName -eq $roleName }
                if ($role) {
                    $user.AddRole($role.RoleId)
                }
            }
            
            # If no roles specified, assign default user role
            if ($user.Roles.Count -eq 0) {
                $defaultRole = $this.Roles.Values | Where-Object { $_.RoleName -eq "User" }
                if ($defaultRole) {
                    $user.AddRole($defaultRole.RoleId)
                }
            }
            
            $this.Users[$user.UserId] = $user
            $this.SaveUsers()
            
            $this.SecurityManager.LogSecurityEvent("User created: $username", "Information")
            
            return $user
        } catch {
            $this.SecurityManager.LogSecurityEvent("Failed to create user: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [AuthenticationToken] AuthenticateUser([string]$username, [string]$password) {
        try {
            # Find user by username or email
            $user = $this.Users.Values | Where-Object { $_.Username -eq $username -or $_.Email -eq $username }
            if (-not $user) {
                $this.SecurityManager.LogSecurityEvent("Authentication failed - user not found: $username", "Warning")
                throw "Invalid username or password"
            }
            
            # Check if account is locked
            if ($user.IsAccountLocked()) {
                $this.SecurityManager.LogSecurityEvent("Authentication failed - account locked: $username", "Warning")
                throw "Account is locked. Please try again later."
            }
            
            # Check if account is active
            if (-not $user.IsActive) {
                $this.SecurityManager.LogSecurityEvent("Authentication failed - account inactive: $username", "Warning")
                throw "Account is inactive"
            }
            
            # Validate password
            if (-not $user.ValidatePassword($password)) {
                $user.FailedLoginAttempts++
                
                if ($user.FailedLoginAttempts -ge $this.MaxFailedAttempts) {
                    $user.LockAccount($this.LockoutDurationMinutes)
                    $this.SecurityManager.LogSecurityEvent("Account locked due to failed login attempts: $username", "Warning")
                }
                
                $this.SaveUsers()
                $this.SecurityManager.LogSecurityEvent("Authentication failed - invalid password: $username", "Warning")
                throw "Invalid username or password"
            }
            
            # Reset failed attempts on successful login
            $user.FailedLoginAttempts = 0
            $user.LastLoginAt = Get-Date
            $this.SaveUsers()
            
            # Create authentication token
            $token = [AuthenticationToken]::new($user.UserId, "Bearer", $this.TokenExpirationMinutes)
            
            # Add user claims to token
            $token.Claims["username"] = $user.Username
            $token.Claims["email"] = $user.Email
            $token.Claims["roles"] = $user.Roles
            
            $this.ActiveTokens[$token.TokenId] = $token
            
            $this.SecurityManager.LogSecurityEvent("User authenticated successfully: $username", "Information")
            
            return $token
        } catch {
            $this.SecurityManager.LogSecurityEvent("Authentication error: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [bool] ValidateToken([string]$tokenId) {
        if (-not $this.ActiveTokens.ContainsKey($tokenId)) {
            return $false
        }
        
        $token = $this.ActiveTokens[$tokenId]
        if (-not $token.IsValid()) {
            # Remove invalid token
            $this.ActiveTokens.Remove($tokenId)
            return $false
        }
        
        return $true
    }
    
    [AIMasterUser] GetUserFromToken([string]$tokenId) {
        if (-not $this.ValidateToken($tokenId)) {
            throw "Invalid token"
        }
        
        $token = $this.ActiveTokens[$tokenId]
        return $this.Users[$token.UserId]
    }
    
    [bool] AuthorizeUserAction([string]$tokenId, [string]$permission) {
        try {
            if (-not $this.ValidateToken($tokenId)) {
                $this.SecurityManager.LogSecurityEvent("Authorization failed - invalid token: $tokenId", "Warning")
                return $false
            }
            
            $token = $this.ActiveTokens[$tokenId]
            $user = $this.Users[$token.UserId]
            
            # Check if user has required permission through roles
            foreach ($roleId in $user.Roles) {
                if ($this.Roles.ContainsKey($roleId)) {
                    $role = $this.Roles[$roleId]
                    if ($role.HasPermission($permission)) {
                        $this.SecurityManager.LogSecurityEvent("Authorization granted: $($user.Username) for $permission", "Information")
                        return $true
                    }
                }
            }
            
            $this.SecurityManager.LogSecurityEvent("Authorization denied: $($user.Username) for $permission", "Warning")
            return $false
        } catch {
            $this.SecurityManager.LogSecurityEvent("Authorization error: $($_.Exception.Message)", "Error")
            return $false
        }
    }
    
    [void] RevokeToken([string]$tokenId) {
        if ($this.ActiveTokens.ContainsKey($tokenId)) {
            $token = $this.ActiveTokens[$tokenId]
            $token.Revoke()
            $this.ActiveTokens.Remove($tokenId)
            
            $this.SecurityManager.LogSecurityEvent("Token revoked: $tokenId", "Information")
        }
    }
    
    [void] RevokeUserTokens([string]$userId) {
        $tokensToRemove = @()
        foreach ($token in $this.ActiveTokens.Values) {
            if ($token.UserId -eq $userId) {
                $token.Revoke()
                $tokensToRemove += $token.TokenId
            }
        }
        
        foreach ($tokenId in $tokensToRemove) {
            $this.ActiveTokens.Remove($tokenId)
        }
        
        if ($tokensToRemove.Count -gt 0) {
            $this.SecurityManager.LogSecurityEvent("Revoked $($tokensToRemove.Count) tokens for user: $userId", "Information")
        }
    }
    
    [AIMasterRole] CreateRole([string]$roleName, [string]$description, [string[]]$permissions) {
        try {
            # Check if role already exists
            $existingRole = $this.Roles.Values | Where-Object { $_.RoleName -eq $roleName }
            if ($existingRole) {
                throw "Role with name '$roleName' already exists"
            }
            
            $role = [AIMasterRole]::new($roleName, $description)
            foreach ($permission in $permissions) {
                $role.AddPermission($permission)
            }
            
            $this.Roles[$role.RoleId] = $role
            $this.SaveRoles()
            
            $this.SecurityManager.LogSecurityEvent("Role created: $roleName", "Information")
            
            return $role
        } catch {
            $this.SecurityManager.LogSecurityEvent("Failed to create role: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [hashtable[]] ListUsers() {
        $results = @()
        foreach ($user in $this.Users.Values) {
            $results += $user.ToHashtable()
        }
        return $results
    }
    
    [hashtable[]] ListRoles() {
        $results = @()
        foreach ($role in $this.Roles.Values) {
            $results += $role.ToHashtable()
        }
        return $results
    }
    
    [hashtable[]] ListActiveTokens() {
        $results = @()
        foreach ($token in $this.ActiveTokens.Values) {
            if ($token.IsValid()) {
                $results += $token.ToHashtable()
            }
        }
        return $results
    }
    
    [void] CleanupExpiredTokens() {
        $expiredTokens = @()
        foreach ($token in $this.ActiveTokens.Values) {
            if (-not $token.IsValid()) {
                $expiredTokens += $token.TokenId
            }
        }
        
        foreach ($tokenId in $expiredTokens) {
            $this.ActiveTokens.Remove($tokenId)
        }
        
        if ($expiredTokens.Count -gt 0) {
            $this.SecurityManager.LogSecurityEvent("Cleaned up $($expiredTokens.Count) expired tokens", "Information")
        }
    }
}

# Export functions
function New-AuthenticationManager {
    <#
    .SYNOPSIS
    Creates a new authentication manager instance.
    
    .DESCRIPTION
    Initializes an authentication manager with user management, role-based access control,
    and session management capabilities.
    
    .PARAMETER SecurityManager
    The security manager instance to use.
    
    .EXAMPLE
    $securityManager = New-SecurityManager -Config $config
    $authManager = New-AuthenticationManager -SecurityManager $securityManager
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [SecurityManager]$SecurityManager
    )
    
    try {
        return [AuthenticationManager]::new($SecurityManager)
    } catch {
        Write-Error "Failed to create authentication manager: $($_.Exception.Message)"
        throw
    }
}

function Add-AIMasterUser {
    <#
    .SYNOPSIS
    Creates a new user account.
    
    .DESCRIPTION
    Creates a new user account with specified username, email, password, and roles.
    
    .PARAMETER AuthManager
    The authentication manager instance.
    
    .PARAMETER Username
    The username for the new account.
    
    .PARAMETER Email
    The email address for the new account.
    
    .PARAMETER Password
    The password for the new account.
    
    .PARAMETER Roles
    Optional roles to assign to the user.
    
    .EXAMPLE
    $user = Add-AIMasterUser -AuthManager $authManager -Username "john.doe" -Email "john@example.com" -Password "SecurePass123!" -Roles @("Developer")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AuthenticationManager]$AuthManager,
        
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [string]$Email,
        
        [Parameter(Mandatory = $true)]
        [string]$Password,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Roles = @()
    )
    
    try {
        return $AuthManager.CreateUser($Username, $Email, $Password, $Roles)
    } catch {
        Write-Error "Failed to create user: $($_.Exception.Message)"
        throw
    }
}

function Invoke-AIMasterAuthentication {
    <#
    .SYNOPSIS
    Authenticates a user and returns an authentication token.
    
    .DESCRIPTION
    Validates user credentials and returns an authentication token for subsequent API calls.
    
    .PARAMETER AuthManager
    The authentication manager instance.
    
    .PARAMETER Username
    The username or email address.
    
    .PARAMETER Password
    The password.
    
    .EXAMPLE
    $token = Invoke-AIMasterAuthentication -AuthManager $authManager -Username "john.doe" -Password "SecurePass123!"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AuthenticationManager]$AuthManager,
        
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [string]$Password
    )
    
    try {
        return $AuthManager.AuthenticateUser($Username, $Password)
    } catch {
        Write-Error "Authentication failed: $($_.Exception.Message)"
        throw
    }
}

function Test-AIMasterAuthorization {
    <#
    .SYNOPSIS
    Tests if a user is authorized to perform a specific action.
    
    .DESCRIPTION
    Validates that a user token has permission to perform a specific operation.
    
    .PARAMETER AuthManager
    The authentication manager instance.
    
    .PARAMETER TokenId
    The authentication token ID.
    
    .PARAMETER Permission
    The permission to check.
    
    .EXAMPLE
    $authorized = Test-AIMasterAuthorization -AuthManager $authManager -TokenId $token.TokenId -Permission "sandbox.create"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AuthenticationManager]$AuthManager,
        
        [Parameter(Mandatory = $true)]
        [string]$TokenId,
        
        [Parameter(Mandatory = $true)]
        [string]$Permission
    )
    
    try {
        return $AuthManager.AuthorizeUserAction($TokenId, $Permission)
    } catch {
        Write-Error "Authorization check failed: $($_.Exception.Message)"
        return $false
    }
}

# Export module members
Export-ModuleMember -Function @(
    'New-AuthenticationManager',
    'Add-AIMasterUser',
    'Invoke-AIMasterAuthentication',
    'Test-AIMasterAuthorization'
) -Variable @() -Cmdlet @() -Alias @()
