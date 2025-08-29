# AIMaster Security Configuration Framework
# Provides comprehensive security controls, environment isolation, and access management

#Requires -Version 7.0
#Requires -Module Microsoft.PowerShell.SecretManagement

using namespace System.Security.Cryptography
using namespace System.Security.Principal
using namespace System.IO

[CmdletBinding()]
param()

# Security Configuration Classes
class AIMasterSecurityConfig {
    [string]$Environment = "Development"
    [hashtable]$AccessControls = @{}
    [hashtable]$ResourceLimits = @{}
    [hashtable]$NetworkRestrictions = @{}
    [hashtable]$FileSystemRestrictions = @{}
    [string]$LoggingLevel = "Information"
    [bool]$AuditEnabled = $true
    [string]$EncryptionKeyId = ""
    [hashtable]$PlatformSettings = @{}
    
    AIMasterSecurityConfig() {
        $this.Initialize()
    }
    
    [void] Initialize() {
        $this.SetDefaultSecuritySettings()
        $this.DetectPlatform()
        $this.ValidateEnvironment()
    }
    
    [void] SetDefaultSecuritySettings() {
        $this.AccessControls = @{
            "RequireAuthentication" = $true
            "SessionTimeout" = 3600  # 1 hour
            "MaxConcurrentSessions" = 5
            "PasswordComplexity" = @{
                "MinLength" = 12
                "RequireUppercase" = $true
                "RequireLowercase" = $true
                "RequireNumbers" = $true
                "RequireSpecialChars" = $true
            }
        }
        
        $this.ResourceLimits = @{
            "MaxMemoryMB" = 1024
            "MaxCpuPercent" = 50
            "MaxDiskSpaceMB" = 5120
            "MaxNetworkBandwidthKbps" = 10240
            "MaxProcesses" = 10
        }
        
        $this.NetworkRestrictions = @{
            "AllowedPorts" = @(80, 443, 8080, 8443)
            "BlockedDomains" = @("*.local", "localhost", "127.0.0.1", "0.0.0.0")
            "RequireHTTPS" = $true
            "MaxConnections" = 100
        }
        
        $this.FileSystemRestrictions = @{
            "AllowedPaths" = @()
            "BlockedPaths" = @(
                "/Users/*/.*",
                "/System/*",
                "/usr/bin/*",
                "/usr/local/bin/*",
                "C:\Windows\*",
                "C:\Program Files\*",
                "C:\Users\*\AppData\*"
            )
            "ReadOnlyPaths" = @("/etc/*", "C:\Windows\System32\*")
            "SandboxRoot" = ""
        }
    }
    
    [void] DetectPlatform() {
        $platform = $null
        if ($IsWindows) {
            $platform = "Windows"
            $this.PlatformSettings["ExecutionPolicy"] = "RemoteSigned"
            $this.PlatformSettings["PowerShellPath"] = "C:\Program Files\PowerShell\7\pwsh.exe"
        } elseif ($IsMacOS) {
            $platform = "macOS"
            $this.PlatformSettings["ExecutionPolicy"] = "RemoteSigned"
            $this.PlatformSettings["PowerShellPath"] = "/usr/local/bin/pwsh"
        } elseif ($IsLinux) {
            $platform = "Linux"
            $this.PlatformSettings["ExecutionPolicy"] = "RemoteSigned"
            $this.PlatformSettings["PowerShellPath"] = "/usr/bin/pwsh"
        }
        
        $this.PlatformSettings["Platform"] = $platform
        $this.PlatformSettings["Architecture"] = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        $this.PlatformSettings["RuntimeIdentifier"] = [System.Runtime.InteropServices.RuntimeInformation]::RuntimeIdentifier
    }
    
    [void] ValidateEnvironment() {
        # Validate that we're running in a secure context
        if ($this.Environment -eq "Production" -and [System.Environment]::GetEnvironmentVariable("AIMASTER_SECURE_MODE") -ne "true") {
            throw "Production environment requires AIMASTER_SECURE_MODE=true"
        }
        
        # Ensure required directories exist
        $this.EnsureSecureDirectories()
    }
    
    [void] EnsureSecureDirectories() {
        $secureRoot = $this.GetSecureRoot()
        $directories = @(
            "$secureRoot/Config",
            "$secureRoot/Logs",
            "$secureRoot/Temp",
            "$secureRoot/Sandbox",
            "$secureRoot/Secrets"
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                if ($IsWindows) {
                    # Set Windows ACL permissions
                    $acl = Get-Acl $dir
                    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                        "FullControl",
                        "ContainerInherit,ObjectInherit",
                        "None",
                        "Allow"
                    )
                    $acl.SetAccessRule($accessRule)
                    Set-Acl -Path $dir -AclObject $acl
                } else {
                    # Set Unix permissions
                    chmod 700 $dir
                }
            }
        }
        
        # Set sandbox root
        $this.FileSystemRestrictions["SandboxRoot"] = "$secureRoot/Sandbox"
    }
    
    [string] GetSecureRoot() {
        $userProfile = if ($IsWindows) { $env:USERPROFILE } else { $env:HOME }
        return Join-Path $userProfile ".aimaster-secure"
    }
}

# Security Manager Class
class SecurityManager {
    [AIMasterSecurityConfig]$Config
    [hashtable]$ActiveSessions = @{}
    [System.Collections.Generic.List[string]]$AuditLog
    
    SecurityManager([AIMasterSecurityConfig]$config) {
        $this.Config = $config
        $this.AuditLog = [System.Collections.Generic.List[string]]::new()
        $this.InitializeSecurity()
    }
    
    [void] InitializeSecurity() {
        $this.LogSecurityEvent("SecurityManager initialized", "Information")
        $this.SetupEncryption()
        $this.EnforceExecutionPolicy()
    }
    
    [void] SetupEncryption() {
        if ([string]::IsNullOrEmpty($this.Config.EncryptionKeyId)) {
            $this.Config.EncryptionKeyId = [System.Guid]::NewGuid().ToString()
        }
        
        # Initialize encryption key in secret store
        try {
            $keyExists = Get-Secret -Name "AIMaster-EncryptionKey-$($this.Config.EncryptionKeyId)" -ErrorAction SilentlyContinue
            if (-not $keyExists) {
                $key = New-Object byte[] 32
                [Security.Cryptography.RandomNumberGenerator]::Fill($key)
                Set-Secret -Name "AIMaster-EncryptionKey-$($this.Config.EncryptionKeyId)" -Secret $key
                $this.LogSecurityEvent("New encryption key generated", "Information")
            }
        } catch {
            $this.LogSecurityEvent("Failed to setup encryption: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [void] EnforceExecutionPolicy() {
        $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
        $requiredPolicy = $this.Config.PlatformSettings["ExecutionPolicy"]
        
        if ($currentPolicy -ne $requiredPolicy) {
            try {
                Set-ExecutionPolicy -ExecutionPolicy $requiredPolicy -Scope CurrentUser -Force
                $this.LogSecurityEvent("Execution policy set to $requiredPolicy", "Information")
            } catch {
                $this.LogSecurityEvent("Failed to set execution policy: $($_.Exception.Message)", "Warning")
            }
        }
    }
    
    [bool] ValidateUserAccess([string]$userId, [string]$operation) {
        if (-not $this.Config.AccessControls["RequireAuthentication"]) {
            return $true
        }
        
        # Check if user has active session
        if ($this.ActiveSessions.ContainsKey($userId)) {
            $session = $this.ActiveSessions[$userId]
            if ($session.ExpiryTime -lt (Get-Date)) {
                $this.ActiveSessions.Remove($userId)
                $this.LogSecurityEvent("Session expired for user: $userId", "Warning")
                return $false
            }
            
            # Update last activity
            $session.LastActivity = Get-Date
            return $true
        }
        
        $this.LogSecurityEvent("Access denied for user: $userId, operation: $operation", "Warning")
        return $false
    }
    
    [string] CreateUserSession([string]$userId) {
        $sessionId = [System.Guid]::NewGuid().ToString()
        $session = @{
            SessionId = $sessionId
            UserId = $userId
            StartTime = Get-Date
            LastActivity = Get-Date
            ExpiryTime = (Get-Date).AddSeconds($this.Config.AccessControls["SessionTimeout"])
        }
        
        $this.ActiveSessions[$userId] = $session
        $this.LogSecurityEvent("Session created for user: $userId", "Information")
        
        return $sessionId
    }
    
    [void] LogSecurityEvent([string]$message, [string]$level) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$level] $message"
        
        if ($this.Config.AuditEnabled) {
            $this.AuditLog.Add($logEntry)
            
            # Write to secure log file
            $logPath = Join-Path $this.Config.GetSecureRoot() "Logs/security.log"
            Add-Content -Path $logPath -Value $logEntry -Force
        }
        
        # Also write to PowerShell streams based on level
        switch ($level) {
            "Error" { Write-Error $message }
            "Warning" { Write-Warning $message }
            "Information" { Write-Information $message }
            "Verbose" { Write-Verbose $message }
            "Debug" { Write-Debug $message }
        }
    }
    
    [string] EncryptData([string]$data) {
        try {
            $key = Get-Secret -Name "AIMaster-EncryptionKey-$($this.Config.EncryptionKeyId)" -AsPlainText
            $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)
            
            using ($aes = [System.Security.Cryptography.Aes]::Create()) {
                $aes.Key = $keyBytes[0..31]  # Use first 32 bytes for AES-256
                $aes.GenerateIV()
                
                $encryptor = $aes.CreateEncryptor()
                $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($data)
                $encryptedBytes = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
                
                # Combine IV and encrypted data
                $result = [byte[]]::new($aes.IV.Length + $encryptedBytes.Length)
                [Array]::Copy($aes.IV, 0, $result, 0, $aes.IV.Length)
                [Array]::Copy($encryptedBytes, 0, $result, $aes.IV.Length, $encryptedBytes.Length)
                
                return [Convert]::ToBase64String($result)
            }
        } catch {
            $this.LogSecurityEvent("Encryption failed: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [string] DecryptData([string]$encryptedData) {
        try {
            $key = Get-Secret -Name "AIMaster-EncryptionKey-$($this.Config.EncryptionKeyId)" -AsPlainText
            $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)
            $dataBytes = [Convert]::FromBase64String($encryptedData)
            
            using ($aes = [System.Security.Cryptography.Aes]::Create()) {
                $aes.Key = $keyBytes[0..31]  # Use first 32 bytes for AES-256
                
                # Extract IV and encrypted data
                $iv = $dataBytes[0..15]  # First 16 bytes are IV
                $encryptedBytes = $dataBytes[16..($dataBytes.Length - 1)]
                
                $aes.IV = $iv
                $decryptor = $aes.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
                
                return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
            }
        } catch {
            $this.LogSecurityEvent("Decryption failed: $($_.Exception.Message)", "Error")
            throw
        }
    }
}

# Export functions
function New-AIMasterSecurityConfig {
    <#
    .SYNOPSIS
    Creates a new AIMaster security configuration.
    
    .DESCRIPTION
    Initializes a comprehensive security configuration for the AIMaster system with platform-specific settings,
    access controls, resource limits, and environment isolation.
    
    .PARAMETER Environment
    The deployment environment (Development, Staging, Production).
    
    .PARAMETER ConfigPath
    Optional path to load existing configuration from.
    
    .EXAMPLE
    $config = New-AIMasterSecurityConfig -Environment "Production"
    
    .EXAMPLE
    $config = New-AIMasterSecurityConfig -Environment "Development" -ConfigPath "/path/to/config.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Development", "Staging", "Production")]
        [string]$Environment = "Development",
        
        [Parameter(Mandatory = $false)]
        [string]$ConfigPath
    )
    
    try {
        $config = [AIMasterSecurityConfig]::new()
        $config.Environment = $Environment
        
        if ($ConfigPath -and (Test-Path $ConfigPath)) {
            $loadedConfig = Get-Content $ConfigPath | ConvertFrom-Json
            # Merge loaded configuration with defaults
            foreach ($property in $loadedConfig.PSObject.Properties) {
                if ($config.PSObject.Properties.Name -contains $property.Name) {
                    $config.$($property.Name) = $property.Value
                }
            }
            Write-Verbose "Configuration loaded from: $ConfigPath"
        }
        
        return $config
    } catch {
        Write-Error "Failed to create security configuration: $($_.Exception.Message)"
        throw
    }
}

function New-SecurityManager {
    <#
    .SYNOPSIS
    Creates a new security manager instance.
    
    .DESCRIPTION
    Initializes a security manager with the provided configuration to enforce security policies,
    manage user sessions, and handle encryption/decryption operations.
    
    .PARAMETER Config
    The AIMaster security configuration object.
    
    .EXAMPLE
    $config = New-AIMasterSecurityConfig -Environment "Production"
    $securityManager = New-SecurityManager -Config $config
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AIMasterSecurityConfig]$Config
    )
    
    try {
        return [SecurityManager]::new($Config)
    } catch {
        Write-Error "Failed to create security manager: $($_.Exception.Message)"
        throw
    }
}

function Save-SecurityConfiguration {
    <#
    .SYNOPSIS
    Saves the security configuration to a file.
    
    .DESCRIPTION
    Serializes and saves the security configuration to a JSON file with proper encryption for sensitive data.
    
    .PARAMETER Config
    The security configuration to save.
    
    .PARAMETER Path
    The file path where to save the configuration.
    
    .PARAMETER SecurityManager
    Optional security manager for encryption.
    
    .EXAMPLE
    Save-SecurityConfiguration -Config $config -Path "/path/to/config.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AIMasterSecurityConfig]$Config,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [SecurityManager]$SecurityManager
    )
    
    try {
        $configJson = $Config | ConvertTo-Json -Depth 10
        
        if ($SecurityManager) {
            $configJson = $SecurityManager.EncryptData($configJson)
        }
        
        $configJson | Set-Content -Path $Path -Force
        Write-Information "Security configuration saved to: $Path"
    } catch {
        Write-Error "Failed to save security configuration: $($_.Exception.Message)"
        throw
    }
}

# Export module members
Export-ModuleMember -Function @(
    'New-AIMasterSecurityConfig',
    'New-SecurityManager', 
    'Save-SecurityConfiguration'
) -Variable @() -Cmdlet @() -Alias @()
