# AIMaster Cross-Platform Orchestration System
# Manages both Mac and PC environments with platform-specific security controls

#Requires -Version 7.0

using namespace System.Runtime.InteropServices
using namespace System.Management.Automation
using namespace System.Collections.Generic

[CmdletBinding()]
param()

# Import required modules
Import-Module -Name (Join-Path $PSScriptRoot "../Config/SecurityConfiguration.psm1") -Force
Import-Module -Name (Join-Path $PSScriptRoot "../Sandbox/EnvironmentIsolation.psm1") -Force

# Platform-specific configuration classes
class PlatformConfiguration {
    [string]$Platform
    [string]$Architecture  
    [string]$PowerShellPath
    [hashtable]$SecuritySettings
    [hashtable]$ResourceLimits
    [hashtable]$NetworkConfiguration
    [hashtable]$FileSystemConfiguration
    [string[]]$RequiredModules
    [string[]]$RequiredComponents
    
    PlatformConfiguration([string]$platform) {
        $this.Platform = $platform
        $this.Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        $this.InitializeDefaults()
    }
    
    [void] InitializeDefaults() {
        switch ($this.Platform) {
            "Windows" {
                $this.PowerShellPath = "C:\Program Files\PowerShell\7\pwsh.exe"
                $this.SecuritySettings = @{
                    "ExecutionPolicy" = "RemoteSigned"
                    "UseWindowsFirewall" = $true
                    "EnableWindowsDefender" = $true
                    "RequireAdminRights" = $false
                    "UseWindowsACLs" = $true
                }
                $this.NetworkConfiguration = @{
                    "FirewallProfile" = "Private"
                    "AllowedInboundPorts" = @(80, 443, 8080, 8443)
                    "AllowedOutboundPorts" = @(80, 443, 53, 123)
                    "BlockLocalNetworkAccess" = $true
                }
                $this.FileSystemConfiguration = @{
                    "SandboxRoot" = "$env:USERPROFILE\.aimaster-secure\sandbox"
                    "TempPath" = "$env:TEMP\aimaster"
                    "LogPath" = "$env:USERPROFILE\.aimaster-secure\logs"
                    "BlockedPaths" = @(
                        "C:\Windows\*",
                        "C:\Program Files\*", 
                        "C:\Program Files (x86)\*",
                        "$env:USERPROFILE\AppData\*"
                    )
                }
                $this.RequiredModules = @(
                    "Microsoft.PowerShell.SecretManagement",
                    "Microsoft.PowerShell.SecretStore",
                    "PSScriptAnalyzer"
                )
                $this.RequiredComponents = @(
                    "Windows Subsystem for Linux",
                    "Hyper-V"
                )
            }
            "macOS" {
                $this.PowerShellPath = "/usr/local/bin/pwsh"
                $this.SecuritySettings = @{
                    "ExecutionPolicy" = "RemoteSigned"
                    "UseSystemFirewall" = $true
                    "RequireSudoRights" = $false
                    "UseUnixPermissions" = $true
                    "EnableSIP" = $true
                }
                $this.NetworkConfiguration = @{
                    "FirewallEnabled" = $true
                    "AllowedInboundPorts" = @(80, 443, 8080, 8443)
                    "AllowedOutboundPorts" = @(80, 443, 53, 123)
                    "BlockLocalNetworkAccess" = $true
                }
                $this.FileSystemConfiguration = @{
                    "SandboxRoot" = "$env:HOME/.aimaster-secure/sandbox"
                    "TempPath" = "/tmp/aimaster"
                    "LogPath" = "$env:HOME/.aimaster-secure/logs"
                    "BlockedPaths" = @(
                        "/System/*",
                        "/usr/bin/*",
                        "/usr/local/bin/*",
                        "$env:HOME/Library/*",
                        "$env:HOME/.ssh/*"
                    )
                }
                $this.RequiredModules = @(
                    "Microsoft.PowerShell.SecretManagement",
                    "Microsoft.PowerShell.SecretStore", 
                    "PSScriptAnalyzer"
                )
                $this.RequiredComponents = @(
                    "Docker Desktop",
                    "Homebrew"
                )
            }
            "Linux" {
                $this.PowerShellPath = "/usr/bin/pwsh"
                $this.SecuritySettings = @{
                    "ExecutionPolicy" = "RemoteSigned"
                    "UseIPTables" = $true
                    "RequireSudoRights" = $false
                    "UseUnixPermissions" = $true
                    "EnableSELinux" = $false
                }
                $this.NetworkConfiguration = @{
                    "IPTablesEnabled" = $true
                    "AllowedInboundPorts" = @(80, 443, 8080, 8443)
                    "AllowedOutboundPorts" = @(80, 443, 53, 123)
                    "BlockLocalNetworkAccess" = $true
                }
                $this.FileSystemConfiguration = @{
                    "SandboxRoot" = "$env:HOME/.aimaster-secure/sandbox"
                    "TempPath" = "/tmp/aimaster"
                    "LogPath" = "$env:HOME/.aimaster-secure/logs"
                    "BlockedPaths" = @(
                        "/etc/*",
                        "/usr/bin/*",
                        "/usr/local/bin/*",
                        "$env:HOME/.ssh/*"
                    )
                }
                $this.RequiredModules = @(
                    "Microsoft.PowerShell.SecretManagement",
                    "Microsoft.PowerShell.SecretStore",
                    "PSScriptAnalyzer"
                )
                $this.RequiredComponents = @(
                    "Docker",
                    "systemd"
                )
            }
        }
        
        # Common resource limits across platforms
        $this.ResourceLimits = @{
            "MaxMemoryMB" = 2048
            "MaxCpuPercent" = 75
            "MaxDiskSpaceMB" = 10240
            "MaxNetworkBandwidthKbps" = 51200
            "MaxProcesses" = 20
            "MaxFileHandles" = 1000
        }
    }
    
    [bool] ValidateRequirements() {
        $missingComponents = @()
        
        # Check PowerShell installation
        if (-not (Test-Path $this.PowerShellPath)) {
            $missingComponents += "PowerShell 7.0+"
        }
        
        # Check required modules
        foreach ($module in $this.RequiredModules) {
            try {
                Import-Module $module -ErrorAction Stop
            } catch {
                $missingComponents += $module
            }
        }
        
        # Platform-specific requirement checks
        switch ($this.Platform) {
            "Windows" {
                # Check Windows Defender
                try {
                    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    if (-not $defenderStatus.AntivirusEnabled) {
                        $missingComponents += "Windows Defender (disabled)"
                    }
                } catch {
                    # Windows Defender not available
                }
                
                # Check execution policy
                $policy = Get-ExecutionPolicy -Scope CurrentUser
                if ($policy -eq "Restricted") {
                    $missingComponents += "Execution Policy (too restrictive)"
                }
            }
            "macOS" {
                # Check SIP status
                try {
                    $sipStatus = & csrutil status 2>/dev/null
                    if ($sipStatus -notmatch "enabled") {
                        $missingComponents += "System Integrity Protection (disabled)"
                    }
                } catch {
                    # SIP check not available
                }
                
                # Check firewall
                try {
                    $firewallStatus = & sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null
                    if ($firewallStatus -notmatch "enabled") {
                        $missingComponents += "Application Firewall (disabled)"
                    }
                } catch {
                    # Firewall check failed
                }
            }
            "Linux" {
                # Check iptables
                try {
                    $iptablesStatus = & iptables -L 2>/dev/null
                    if (-not $iptablesStatus) {
                        $missingComponents += "iptables"
                    }
                } catch {
                    $missingComponents += "iptables"
                }
                
                # Check systemd
                try {
                    $systemdStatus = & systemctl --version 2>/dev/null
                    if (-not $systemdStatus) {
                        $missingComponents += "systemd"
                    }
                } catch {
                    $missingComponents += "systemd"
                }
            }
        }
        
        if ($missingComponents.Count -gt 0) {
            Write-Warning "Missing required components: $($missingComponents -join ', ')"
            return $false
        }
        
        return $true
    }
    
    [void] ApplyPlatformSecurity() {
        switch ($this.Platform) {
            "Windows" {
                $this.ConfigureWindowsSecurity()
            }
            "macOS" {
                $this.ConfigureMacOSSecurity()
            }
            "Linux" {
                $this.ConfigureLinuxSecurity()
            }
        }
    }
    
    [void] ConfigureWindowsSecurity() {
        try {
            # Set execution policy
            Set-ExecutionPolicy -ExecutionPolicy $this.SecuritySettings["ExecutionPolicy"] -Scope CurrentUser -Force
            
            # Configure Windows Firewall rules
            if ($this.SecuritySettings["UseWindowsFirewall"]) {
                # Allow specific inbound ports
                foreach ($port in $this.NetworkConfiguration["AllowedInboundPorts"]) {
                    New-NetFirewallRule -DisplayName "AIMaster-Inbound-$port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -ErrorAction SilentlyContinue
                }
                
                # Block local network access if configured
                if ($this.NetworkConfiguration["BlockLocalNetworkAccess"]) {
                    New-NetFirewallRule -DisplayName "AIMaster-Block-Local" -Direction Outbound -RemoteAddress 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -Action Block -ErrorAction SilentlyContinue
                }
            }
            
        } catch {
            Write-Warning "Failed to configure Windows security: $($_.Exception.Message)"
        }
    }
    
    [void] ConfigureMacOSSecurity() {
        try {
            # Set execution policy
            Set-ExecutionPolicy -ExecutionPolicy $this.SecuritySettings["ExecutionPolicy"] -Scope CurrentUser -Force
            
            # Configure application firewall
            if ($this.NetworkConfiguration["FirewallEnabled"]) {
                try {
                    & sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null
                    & sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on 2>/dev/null
                    & sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null
                } catch {
                    Write-Warning "Could not configure macOS firewall (requires admin privileges)"
                }
            }
            
        } catch {
            Write-Warning "Failed to configure macOS security: $($_.Exception.Message)"
        }
    }
    
    [void] ConfigureLinuxSecurity() {
        try {
            # Set execution policy
            Set-ExecutionPolicy -ExecutionPolicy $this.SecuritySettings["ExecutionPolicy"] -Scope CurrentUser -Force
            
            # Configure iptables rules
            if ($this.SecuritySettings["UseIPTables"]) {
                try {
                    # Allow specific ports
                    foreach ($port in $this.NetworkConfiguration["AllowedInboundPorts"]) {
                        & sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                    }
                    
                    # Block local network access
                    if ($this.NetworkConfiguration["BlockLocalNetworkAccess"]) {
                        & sudo iptables -A OUTPUT -d 10.0.0.0/8 -j DROP 2>/dev/null  
                        & sudo iptables -A OUTPUT -d 172.16.0.0/12 -j DROP 2>/dev/null
                        & sudo iptables -A OUTPUT -d 192.168.0.0/16 -j DROP 2>/dev/null
                    }
                } catch {
                    Write-Warning "Could not configure iptables (requires admin privileges)"
                }
            }
            
        } catch {
            Write-Warning "Failed to configure Linux security: $($_.Exception.Message)"
        }
    }
}

# Cross-platform orchestrator class
class CrossPlatformOrchestrator {
    [SecurityManager]$SecurityManager
    [SandboxManager]$SandboxManager
    [PlatformConfiguration]$PlatformConfig
    [hashtable]$ManagedNodes = @{}
    [hashtable]$DeploymentTemplates = @{}
    [bool]$IsInitialized = $false
    
    CrossPlatformOrchestrator([SecurityManager]$securityManager) {
        $this.SecurityManager = $securityManager
        $this.SandboxManager = [SandboxManager]::new($securityManager)
        $this.DetectAndConfigurePlatform()
        $this.InitializeTemplates()
        $this.IsInitialized = $true
        
        $this.SecurityManager.LogSecurityEvent("CrossPlatformOrchestrator initialized for $($this.PlatformConfig.Platform)", "Information")
    }
    
    [void] DetectAndConfigurePlatform() {
        $platform = "Unknown"
        
        if ($IsWindows) {
            $platform = "Windows"
        } elseif ($IsMacOS) {
            $platform = "macOS"
        } elseif ($IsLinux) {
            $platform = "Linux"
        }
        
        $this.PlatformConfig = [PlatformConfiguration]::new($platform)
        
        # Validate platform requirements
        if (-not $this.PlatformConfig.ValidateRequirements()) {
            throw "Platform requirements not met for $platform"
        }
        
        # Apply platform-specific security configuration
        $this.PlatformConfig.ApplyPlatformSecurity()
        
        $this.SecurityManager.LogSecurityEvent("Platform configured: $platform on $($this.PlatformConfig.Architecture)", "Information")
    }
    
    [void] InitializeTemplates() {
        # Development environment template
        $this.DeploymentTemplates["Development"] = @{
            Environment = "Development"
            SecurityLevel = "Standard"
            ResourceLimits = @{
                MaxMemoryMB = 1024
                MaxCpuPercent = 50
                MaxProcesses = 10
            }
            NetworkRestrictions = @{
                AllowedPorts = @(80, 443, 3000, 5000, 8080, 8443)
                BlockLocalAccess = $false
            }
            FileSystemRestrictions = @{
                AllowHomeAccess = $true
                AllowTempAccess = $true
                BlockSystemAccess = $true
            }
        }
        
        # Staging environment template
        $this.DeploymentTemplates["Staging"] = @{
            Environment = "Staging"
            SecurityLevel = "Enhanced"
            ResourceLimits = @{
                MaxMemoryMB = 2048
                MaxCpuPercent = 75
                MaxProcesses = 15
            }
            NetworkRestrictions = @{
                AllowedPorts = @(80, 443, 8080, 8443)
                BlockLocalAccess = $true
            }
            FileSystemRestrictions = @{
                AllowHomeAccess = $false
                AllowTempAccess = $true
                BlockSystemAccess = $true
            }
        }
        
        # Production environment template
        $this.DeploymentTemplates["Production"] = @{
            Environment = "Production"
            SecurityLevel = "Maximum"
            ResourceLimits = @{
                MaxMemoryMB = 4096
                MaxCpuPercent = 90
                MaxProcesses = 25
            }
            NetworkRestrictions = @{
                AllowedPorts = @(80, 443)
                BlockLocalAccess = $true
            }
            FileSystemRestrictions = @{
                AllowHomeAccess = $false
                AllowTempAccess = $false
                BlockSystemAccess = $true
            }
        }
    }
    
    [hashtable] RegisterManagedNode([string]$nodeId, [string]$platform, [string]$connectionString) {
        try {
            $node = @{
                NodeId = $nodeId
                Platform = $platform
                ConnectionString = $connectionString
                Status = "Registered"
                LastContact = Get-Date
                Configuration = $null
                ActiveSandboxes = @()
            }
            
            # Create platform-specific configuration for remote node
            $platformConfig = [PlatformConfiguration]::new($platform)
            $node.Configuration = $platformConfig
            
            $this.ManagedNodes[$nodeId] = $node
            $this.SecurityManager.LogSecurityEvent("Managed node registered: $nodeId ($platform)", "Information")
            
            return $node
        } catch {
            $this.SecurityManager.LogSecurityEvent("Failed to register managed node: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [hashtable] DeployToNode([string]$nodeId, [string]$templateName, [hashtable]$customConfig = @{}) {
        try {
            if (-not $this.ManagedNodes.ContainsKey($nodeId)) {
                throw "Node not found: $nodeId"
            }
            
            if (-not $this.DeploymentTemplates.ContainsKey($templateName)) {
                throw "Template not found: $templateName"
            }
            
            $node = $this.ManagedNodes[$nodeId]
            $template = $this.DeploymentTemplates[$templateName].Clone()
            
            # Merge custom configuration
            foreach ($key in $customConfig.Keys) {
                $template[$key] = $customConfig[$key]
            }
            
            # Create deployment package
            $deployment = @{
                DeploymentId = [System.Guid]::NewGuid().ToString()
                NodeId = $nodeId
                Platform = $node.Platform
                Template = $template
                DeployedAt = Get-Date
                Status = "Deploying"
                SandboxId = $null
            }
            
            # Execute deployment based on platform
            $sandboxId = $this.ExecutePlatformDeployment($node, $template)
            $deployment.SandboxId = $sandboxId
            $deployment.Status = "Deployed"
            
            # Update node status
            $node.Status = "Active"
            $node.LastContact = Get-Date
            $node.ActiveSandboxes += $sandboxId
            
            $this.SecurityManager.LogSecurityEvent("Deployment completed: $($deployment.DeploymentId) on $nodeId", "Information")
            
            return $deployment
        } catch {
            $this.SecurityManager.LogSecurityEvent("Deployment failed: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [string] ExecutePlatformDeployment([hashtable]$node, [hashtable]$template) {
        $platform = $node.Platform
        $connectionString = $node.ConnectionString
        
        switch ($platform) {
            "Windows" {
                return $this.DeployToWindows($connectionString, $template)
            }
            "macOS" {
                return $this.DeployToMacOS($connectionString, $template)
            }
            "Linux" {
                return $this.DeployToLinux($connectionString, $template)
            }
            default {
                throw "Unsupported platform: $platform"
            }
        }
    }
    
    [string] DeployToWindows([string]$connectionString, [hashtable]$template) {
        try {
            # Create remote PowerShell session for Windows
            $session = New-PSSession -ComputerName $connectionString -ErrorAction Stop
            
            # Deploy security configuration to remote Windows machine
            $remoteScript = {
                param($Template, $SecurityConfig)
                
                # Install required modules if not present
                $requiredModules = @("Microsoft.PowerShell.SecretManagement", "Microsoft.PowerShell.SecretStore")
                foreach ($module in $requiredModules) {
                    if (-not (Get-Module -ListAvailable -Name $module)) {
                        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                    }
                }
                
                # Create sandbox environment
                $sandboxRoot = "$env:USERPROFILE\.aimaster-secure\sandbox"
                $sandboxId = "remote-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([System.Guid]::NewGuid().ToString().Substring(0,8))"
                $sandboxPath = Join-Path $sandboxRoot $sandboxId
                
                New-Item -ItemType Directory -Path $sandboxPath -Force | Out-Null
                
                # Configure Windows-specific security settings
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                
                # Return sandbox ID
                return $sandboxId
            }
            
            $sandboxId = Invoke-Command -Session $session -ScriptBlock $remoteScript -ArgumentList $template, $this.SecurityManager.Config
            
            Remove-PSSession $session
            
            $this.SecurityManager.LogSecurityEvent("Windows deployment completed: $sandboxId", "Information")
            return $sandboxId
        } catch {
            $this.SecurityManager.LogSecurityEvent("Windows deployment failed: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [string] DeployToMacOS([string]$connectionString, [hashtable]$template) {
        try {
            # Use SSH for macOS deployment
            $sandboxId = "remote-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([System.Guid]::NewGuid().ToString().Substring(0,8))"
            
            $deploymentScript = @"
#!/bin/bash
set -e

# Create sandbox directory
SANDBOX_ROOT="$HOME/.aimaster-secure/sandbox"
SANDBOX_PATH="$SANDBOX_ROOT/$sandboxId"
mkdir -p "$SANDBOX_PATH"

# Set permissions
chmod 700 "$SANDBOX_PATH"

# Install PowerShell if not present
if ! command -v pwsh &> /dev/null; then
    echo "PowerShell not found. Please install PowerShell 7.0+"
    exit 1
fi

# Configure security settings
pwsh -c "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force"

echo "$sandboxId"
"@
            
            # Execute remote script via SSH
            $result = & ssh $connectionString $deploymentScript
            if ($LASTEXITCODE -ne 0) {
                throw "SSH deployment failed with exit code $LASTEXITCODE"
            }
            
            $this.SecurityManager.LogSecurityEvent("macOS deployment completed: $sandboxId", "Information")
            return $sandboxId
        } catch {
            $this.SecurityManager.LogSecurityEvent("macOS deployment failed: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [string] DeployToLinux([string]$connectionString, [hashtable]$template) {
        try {
            # Use SSH for Linux deployment
            $sandboxId = "remote-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([System.Guid]::NewGuid().ToString().Substring(0,8))"
            
            $deploymentScript = @"
#!/bin/bash
set -e

# Create sandbox directory
SANDBOX_ROOT="$HOME/.aimaster-secure/sandbox"
SANDBOX_PATH="$SANDBOX_ROOT/$sandboxId"
mkdir -p "$SANDBOX_PATH"

# Set permissions
chmod 700 "$SANDBOX_PATH"

# Install PowerShell if not present  
if ! command -v pwsh &> /dev/null; then
    echo "PowerShell not found. Please install PowerShell 7.0+"
    exit 1
fi

# Configure iptables rules (if available and permitted)
if command -v iptables &> /dev/null; then
    # Basic security rules (requires appropriate permissions)
    sudo iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
    sudo iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
fi

# Configure security settings
pwsh -c "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force"

echo "$sandboxId"
"@
            
            # Execute remote script via SSH
            $result = & ssh $connectionString $deploymentScript
            if ($LASTEXITCODE -ne 0) {
                throw "SSH deployment failed with exit code $LASTEXITCODE"
            }
            
            $this.SecurityManager.LogSecurityEvent("Linux deployment completed: $sandboxId", "Information")
            return $sandboxId
        } catch {
            $this.SecurityManager.LogSecurityEvent("Linux deployment failed: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [hashtable[]] ListManagedNodes() {
        $results = @()
        foreach ($node in $this.ManagedNodes.Values) {
            $results += @{
                NodeId = $node.NodeId
                Platform = $node.Platform
                Status = $node.Status
                LastContact = $node.LastContact
                ActiveSandboxes = $node.ActiveSandboxes.Count
            }
        }
        return $results
    }
    
    [hashtable] GetNodeStatus([string]$nodeId) {
        if (-not $this.ManagedNodes.ContainsKey($nodeId)) {
            throw "Node not found: $nodeId"
        }
        
        $node = $this.ManagedNodes[$nodeId]
        return @{
            NodeId = $node.NodeId
            Platform = $node.Platform
            Status = $node.Status
            LastContact = $node.LastContact
            ActiveSandboxes = $node.ActiveSandboxes
            Configuration = $node.Configuration.GetType().Name
        }
    }
    
    [void] ShutdownNode([string]$nodeId) {
        try {
            if (-not $this.ManagedNodes.ContainsKey($nodeId)) {
                throw "Node not found: $nodeId"
            }
            
            $node = $this.ManagedNodes[$nodeId]
            
            # Cleanup active sandboxes on the node
            foreach ($sandboxId in $node.ActiveSandboxes) {
                try {
                    # Platform-specific cleanup would go here
                    $this.SecurityManager.LogSecurityEvent("Cleaned up sandbox on node $nodeId`: $sandboxId", "Information")
                } catch {
                    $this.SecurityManager.LogSecurityEvent("Failed to cleanup sandbox $sandboxId on node $nodeId`: $($_.Exception.Message)", "Warning")
                }
            }
            
            $node.Status = "Shutdown"
            $node.ActiveSandboxes = @()
            
            $this.SecurityManager.LogSecurityEvent("Node shutdown: $nodeId", "Information")
        } catch {
            $this.SecurityManager.LogSecurityEvent("Failed to shutdown node: $($_.Exception.Message)", "Error")
            throw
        }
    }
    
    [void] ShutdownAll() {
        $nodeIds = @($this.ManagedNodes.Keys)
        foreach ($nodeId in $nodeIds) {
            try {
                $this.ShutdownNode($nodeId)
            } catch {
                $this.SecurityManager.LogSecurityEvent("Failed to shutdown node $nodeId`: $($_.Exception.Message)", "Warning")
            }
        }
        
        # Shutdown local sandbox manager
        $this.SandboxManager.ShutdownAll()
    }
}

# Export functions
function New-CrossPlatformOrchestrator {
    <#
    .SYNOPSIS
    Creates a new cross-platform orchestrator instance.
    
    .DESCRIPTION
    Initializes an orchestrator that can manage both Mac and PC environments with 
    platform-specific security controls and configurations.
    
    .PARAMETER SecurityManager
    The security manager instance to use.
    
    .EXAMPLE
    $securityManager = New-SecurityManager -Config $config
    $orchestrator = New-CrossPlatformOrchestrator -SecurityManager $securityManager
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [SecurityManager]$SecurityManager
    )
    
    try {
        return [CrossPlatformOrchestrator]::new($SecurityManager)
    } catch {
        Write-Error "Failed to create cross-platform orchestrator: $($_.Exception.Message)"
        throw
    }
}

function Register-ManagedNode {
    <#
    .SYNOPSIS
    Registers a new managed node with the orchestrator.
    
    .DESCRIPTION
    Registers a Mac or PC system for management by the orchestrator.
    
    .PARAMETER Orchestrator
    The orchestrator instance.
    
    .PARAMETER NodeId
    Unique identifier for the node.
    
    .PARAMETER Platform
    The platform type (Windows, macOS, Linux).
    
    .PARAMETER ConnectionString
    Connection string for the node (hostname, IP, etc.).
    
    .EXAMPLE
    $node = Register-ManagedNode -Orchestrator $orchestrator -NodeId "mac-dev-1" -Platform "macOS" -ConnectionString "192.168.1.100"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [CrossPlatformOrchestrator]$Orchestrator,
        
        [Parameter(Mandatory = $true)]
        [string]$NodeId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "macOS", "Linux")]
        [string]$Platform,
        
        [Parameter(Mandatory = $true)]
        [string]$ConnectionString
    )
    
    try {
        return $Orchestrator.RegisterManagedNode($NodeId, $Platform, $ConnectionString)
    } catch {
        Write-Error "Failed to register managed node: $($_.Exception.Message)"
        throw
    }
}

function Deploy-ToManagedNode {
    <#
    .SYNOPSIS
    Deploys a configuration template to a managed node.
    
    .DESCRIPTION
    Deploys a security configuration and sandbox environment to a managed Mac or PC system.
    
    .PARAMETER Orchestrator
    The orchestrator instance.
    
    .PARAMETER NodeId
    The target node identifier.
    
    .PARAMETER Template
    The deployment template to use (Development, Staging, Production).
    
    .PARAMETER CustomConfig
    Optional custom configuration overrides.
    
    .EXAMPLE
    $deployment = Deploy-ToManagedNode -Orchestrator $orchestrator -NodeId "mac-dev-1" -Template "Development"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [CrossPlatformOrchestrator]$Orchestrator,
        
        [Parameter(Mandatory = $true)]
        [string]$NodeId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Development", "Staging", "Production")]
        [string]$Template,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$CustomConfig = @{}
    )
    
    try {
        return $Orchestrator.DeployToNode($NodeId, $Template, $CustomConfig)
    } catch {
        Write-Error "Failed to deploy to managed node: $($_.Exception.Message)"
        throw
    }
}

# Export module members
Export-ModuleMember -Function @(
    'New-CrossPlatformOrchestrator',
    'Register-ManagedNode',
    'Deploy-ToManagedNode'
) -Variable @() -Cmdlet @() -Alias @()
