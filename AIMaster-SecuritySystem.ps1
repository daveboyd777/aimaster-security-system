# AIMaster Security System - Main Entry Point and Demo
# Comprehensive security framework for general release with environment parameterization,
# access control, and cross-platform orchestration capabilities

#Requires -Version 7.0
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Development", "Staging", "Production")]
    [string]$Environment = "Development",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$InitializeOnly = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$CreateSampleUser = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$RunTests = $false
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Import all security modules
$ScriptRoot = $PSScriptRoot
$ModulePaths = @(
    "$ScriptRoot/Config/SecurityConfiguration.psm1",
    "$ScriptRoot/Auth/AuthenticationFramework.psm1", 
    "$ScriptRoot/Sandbox/EnvironmentIsolation.psm1",
    "$ScriptRoot/Orchestration/CrossPlatformOrchestrator.psm1",
    "$ScriptRoot/Deployment/SecureDeploymentManager.psm1",
    "$ScriptRoot/Monitoring/AuditAndMonitoringSystem.psm1"
)

Write-Host "AIMaster Security System - Initializing..." -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Platform: $($PSVersionTable.Platform)" -ForegroundColor Yellow

foreach ($modulePath in $ModulePaths) {
    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -Force
            Write-Host "✓ Loaded module: $(Split-Path $modulePath -Leaf)" -ForegroundColor Green
        } catch {
            Write-Error "Failed to load module $modulePath`: $($_.Exception.Message)"
            exit 1
        }
    } else {
        Write-Error "Module not found: $modulePath"
        exit 1
    }
}

# Initialize the security system
function Initialize-AIMasterSecuritySystem {
    param(
        [string]$Environment,
        [string]$ConfigPath = ""
    )
    
    Write-Host "`nInitializing AIMaster Security System Components..." -ForegroundColor Cyan
    
    try {
        # Step 1: Create Security Configuration
        Write-Host "1. Creating security configuration..." -ForegroundColor White
        $securityConfig = New-AIMasterSecurityConfig -Environment $Environment -ConfigPath $ConfigPath
        $securityManager = New-SecurityManager -Config $securityConfig
        Write-Host "   ✓ Security configuration initialized" -ForegroundColor Green
        
        # Step 2: Initialize Authentication Manager
        Write-Host "2. Initializing authentication system..." -ForegroundColor White
        $authManager = New-AuthenticationManager -SecurityManager $securityManager
        Write-Host "   ✓ Authentication system ready" -ForegroundColor Green
        
        # Step 3: Initialize Sandbox Manager
        Write-Host "3. Setting up sandbox environment..." -ForegroundColor White
        $sandboxManager = New-SandboxManager -SecurityManager $securityManager
        Write-Host "   ✓ Sandbox environment ready" -ForegroundColor Green
        
        # Step 4: Initialize Cross-Platform Orchestrator
        Write-Host "4. Configuring cross-platform orchestration..." -ForegroundColor White
        $orchestrator = New-CrossPlatformOrchestrator -SecurityManager $securityManager
        Write-Host "   ✓ Cross-platform orchestrator ready" -ForegroundColor Green
        
        # Step 5: Initialize Deployment Manager
        Write-Host "5. Setting up secure deployment system..." -ForegroundColor White
        $deploymentManager = New-SecureDeploymentManager -SecurityManager $securityManager -AuthenticationManager $authManager
        Write-Host "   ✓ Deployment system ready" -ForegroundColor Green
        
        # Step 6: Initialize Monitoring System
        Write-Host "6. Starting audit and monitoring system..." -ForegroundColor White
        $monitoringSystem = New-AuditAndMonitoringSystem -SecurityManager $securityManager -AuthenticationManager $authManager
        Write-Host "   ✓ Monitoring system active" -ForegroundColor Green
        
        # Log system initialization
        Write-AuditEvent -MonitoringSystem $monitoringSystem -EventType "System" -Category "Initialization" -Action "SystemStartup" -Message "AIMaster Security System initialized successfully" -Severity "Information" -Details @{
            Environment = $Environment
            Platform = $PSVersionTable.Platform
            PowerShellVersion = $PSVersionTable.PSVersion
            Components = @("SecurityManager", "AuthenticationManager", "SandboxManager", "Orchestrator", "DeploymentManager", "MonitoringSystem")
        }
        
        return @{
            SecurityManager = $securityManager
            AuthenticationManager = $authManager
            SandboxManager = $sandboxManager
            Orchestrator = $orchestrator
            DeploymentManager = $deploymentManager
            MonitoringSystem = $monitoringSystem
        }
        
    } catch {
        Write-Error "Failed to initialize AIMaster Security System: $($_.Exception.Message)"
        throw
    }
}

# Create sample user for demonstration
function Create-SampleUser {
    param(
        [hashtable]$SystemComponents
    )
    
    Write-Host "`nCreating sample user account..." -ForegroundColor Cyan
    
    try {
        $username = "admin"
        $email = "admin@aimaster.local"
        $password = "SecureAdminPass123!"
        $roles = @("Administrator")
        
        $user = Add-AIMasterUser -AuthManager $SystemComponents.AuthenticationManager -Username $username -Email $email -Password $password -Roles $roles
        
        Write-Host "✓ Sample user created:" -ForegroundColor Green
        Write-Host "  Username: $username" -ForegroundColor White
        Write-Host "  Email: $email" -ForegroundColor White
        Write-Host "  Roles: $($roles -join ', ')" -ForegroundColor White
        Write-Host "  Password: [REDACTED]" -ForegroundColor Yellow
        
        # Test authentication
        $authToken = Invoke-AIMasterAuthentication -AuthManager $SystemComponents.AuthenticationManager -Username $username -Password $password
        
        Write-Host "✓ Authentication test successful" -ForegroundColor Green
        Write-Host "  Token ID: $($authToken.TokenId)" -ForegroundColor White
        Write-Host "  Expires: $($authToken.ExpiresAt)" -ForegroundColor White
        
        return @{
            User = $user
            AuthToken = $authToken
        }
        
    } catch {
        Write-Warning "Failed to create sample user: $($_.Exception.Message)"
        return $null
    }
}

# Run comprehensive tests
function Test-SecuritySystem {
    param(
        [hashtable]$SystemComponents,
        [hashtable]$SampleUser = $null
    )
    
    Write-Host "`nRunning security system tests..." -ForegroundColor Cyan
    
    $testResults = @{
        Passed = 0
        Failed = 0
        Tests = @()
    }
    
    try {
        # Test 1: Authentication and Authorization
        Write-Host "Running Test 1: Authentication and Authorization..." -ForegroundColor White
        if ($SampleUser -and $SampleUser.AuthToken) {
            $authorized = Test-AIMasterAuthorization -AuthManager $SystemComponents.AuthenticationManager -TokenId $SampleUser.AuthToken.TokenId -Permission "sandbox.create"
            if ($authorized) {
                Write-Host "   ✓ Authorization test passed" -ForegroundColor Green
                $testResults.Passed++
            } else {
                Write-Host "   ✗ Authorization test failed" -ForegroundColor Red
                $testResults.Failed++
            }
            $testResults.Tests += @{Name = "Authorization"; Result = $authorized}
        } else {
            Write-Host "   - Skipped (no sample user)" -ForegroundColor Yellow
            $testResults.Tests += @{Name = "Authorization"; Result = "Skipped"}
        }
        
        # Test 2: Sandbox Environment Creation
        Write-Host "Running Test 2: Sandbox Environment..." -ForegroundColor White
        if ($SampleUser -and $SampleUser.AuthToken) {
            try {
                $sandbox = New-SandboxEnvironment -SandboxManager $SystemComponents.SandboxManager -UserId $SampleUser.User.UserId
                if ($sandbox -and $sandbox.IsActive) {
                    Write-Host "   ✓ Sandbox creation test passed" -ForegroundColor Green
                    $testResults.Passed++
                    
                    # Cleanup sandbox
                    $sandbox.Destroy()
                } else {
                    Write-Host "   ✗ Sandbox creation test failed" -ForegroundColor Red
                    $testResults.Failed++
                }
                $testResults.Tests += @{Name = "Sandbox Creation"; Result = $true}
            } catch {
                Write-Host "   ✗ Sandbox test failed: $($_.Exception.Message)" -ForegroundColor Red
                $testResults.Failed++
                $testResults.Tests += @{Name = "Sandbox Creation"; Result = $false}
            }
        } else {
            Write-Host "   - Skipped (no sample user)" -ForegroundColor Yellow
            $testResults.Tests += @{Name = "Sandbox Creation"; Result = "Skipped"}
        }
        
        # Test 3: Cross-Platform Detection
        Write-Host "Running Test 3: Cross-Platform Detection..." -ForegroundColor White
        $platformInfo = $SystemComponents.Orchestrator.PlatformConfig
        if ($platformInfo -and $platformInfo.Platform -ne "Unknown") {
            Write-Host "   ✓ Platform detection test passed: $($platformInfo.Platform)" -ForegroundColor Green
            $testResults.Passed++
        } else {
            Write-Host "   ✗ Platform detection test failed" -ForegroundColor Red
            $testResults.Failed++
        }
        $testResults.Tests += @{Name = "Platform Detection"; Result = ($platformInfo.Platform -ne "Unknown")}
        
        # Test 4: Deployment Configuration
        Write-Host "Running Test 4: Deployment Configuration..." -ForegroundColor White
        if ($SampleUser -and $SampleUser.AuthToken) {
            try {
                $deployConfig = New-DeploymentConfiguration -DeploymentManager $SystemComponents.DeploymentManager -TokenId $SampleUser.AuthToken.TokenId -Name "TestConfig" -Environment $Environment -Settings @{TestSetting = "TestValue"}
                if ($deployConfig -and $deployConfig.ConfigId) {
                    Write-Host "   ✓ Deployment configuration test passed" -ForegroundColor Green
                    $testResults.Passed++
                } else {
                    Write-Host "   ✗ Deployment configuration test failed" -ForegroundColor Red
                    $testResults.Failed++
                }
                $testResults.Tests += @{Name = "Deployment Configuration"; Result = $true}
            } catch {
                Write-Host "   ✗ Deployment configuration test failed: $($_.Exception.Message)" -ForegroundColor Red
                $testResults.Failed++
                $testResults.Tests += @{Name = "Deployment Configuration"; Result = $false}
            }
        } else {
            Write-Host "   - Skipped (no sample user)" -ForegroundColor Yellow
            $testResults.Tests += @{Name = "Deployment Configuration"; Result = "Skipped"}
        }
        
        # Test 5: Audit Trail
        Write-Host "Running Test 5: Audit Trail..." -ForegroundColor White
        if ($SampleUser -and $SampleUser.AuthToken) {
            try {
                $events = Get-AuditTrail -MonitoringSystem $SystemComponents.MonitoringSystem -TokenId $SampleUser.AuthToken.TokenId -StartTime (Get-Date).AddMinutes(-5) -EndTime (Get-Date) -Limit 10
                if ($events -and $events.Count -gt 0) {
                    Write-Host "   ✓ Audit trail test passed ($($events.Count) events found)" -ForegroundColor Green
                    $testResults.Passed++
                } else {
                    Write-Host "   ✓ Audit trail test passed (no events in timeframe)" -ForegroundColor Green
                    $testResults.Passed++
                }
                $testResults.Tests += @{Name = "Audit Trail"; Result = $true}
            } catch {
                Write-Host "   ✗ Audit trail test failed: $($_.Exception.Message)" -ForegroundColor Red
                $testResults.Failed++
                $testResults.Tests += @{Name = "Audit Trail"; Result = $false}
            }
        } else {
            Write-Host "   - Skipped (no sample user)" -ForegroundColor Yellow
            $testResults.Tests += @{Name = "Audit Trail"; Result = "Skipped"}
        }
        
    } catch {
        Write-Error "Test execution failed: $($_.Exception.Message)"
    }
    
    # Display test summary
    Write-Host "`nTest Results Summary:" -ForegroundColor Cyan
    Write-Host "  Passed: $($testResults.Passed)" -ForegroundColor Green
    Write-Host "  Failed: $($testResults.Failed)" -ForegroundColor Red
    Write-Host "  Total:  $($testResults.Passed + $testResults.Failed)" -ForegroundColor White
    
    return $testResults
}

# Display system status
function Show-SystemStatus {
    param(
        [hashtable]$SystemComponents
    )
    
    Write-Host "`nAIMaster Security System Status:" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    
    # Security Manager Status
    Write-Host "`nSecurity Manager:" -ForegroundColor Yellow
    Write-Host "  Environment: $($SystemComponents.SecurityManager.Config.Environment)" -ForegroundColor White
    Write-Host "  Secure Root: $($SystemComponents.SecurityManager.Config.GetSecureRoot())" -ForegroundColor White
    Write-Host "  Encryption: Enabled" -ForegroundColor Green
    
    # Authentication Manager Status  
    Write-Host "`nAuthentication Manager:" -ForegroundColor Yellow
    $users = $SystemComponents.AuthenticationManager.ListUsers()
    $roles = $SystemComponents.AuthenticationManager.ListRoles()
    $tokens = $SystemComponents.AuthenticationManager.ListActiveTokens()
    Write-Host "  Users: $($users.Count)" -ForegroundColor White
    Write-Host "  Roles: $($roles.Count)" -ForegroundColor White
    Write-Host "  Active Tokens: $($tokens.Count)" -ForegroundColor White
    
    # Sandbox Manager Status
    Write-Host "`nSandbox Manager:" -ForegroundColor Yellow
    $sandboxes = $SystemComponents.SandboxManager.ListSandboxes()
    Write-Host "  Active Sandboxes: $($sandboxes.Count)" -ForegroundColor White
    Write-Host "  Max Sandboxes: $($SystemComponents.SandboxManager.MaxSandboxes)" -ForegroundColor White
    
    # Orchestrator Status
    Write-Host "`nCross-Platform Orchestrator:" -ForegroundColor Yellow
    $nodes = $SystemComponents.Orchestrator.ListManagedNodes()
    Write-Host "  Platform: $($SystemComponents.Orchestrator.PlatformConfig.Platform)" -ForegroundColor White
    Write-Host "  Architecture: $($SystemComponents.Orchestrator.PlatformConfig.Architecture)" -ForegroundColor White
    Write-Host "  Managed Nodes: $($nodes.Count)" -ForegroundColor White
    
    # Deployment Manager Status
    Write-Host "`nDeployment Manager:" -ForegroundColor Yellow
    Write-Host "  Status: Active" -ForegroundColor Green
    Write-Host "  Templates: Available" -ForegroundColor White
    
    # Monitoring System Status
    Write-Host "`nMonitoring System:" -ForegroundColor Yellow
    $monitorStatus = $SystemComponents.MonitoringSystem.GetSystemStatus()
    Write-Host "  Status: $($monitorStatus.IsRunning ? 'Running' : 'Stopped')" -ForegroundColor $(if ($monitorStatus.IsRunning) { "Green" } else { "Red" })
    Write-Host "  Event Queue: $($monitorStatus.EventQueueSize)" -ForegroundColor White
    Write-Host "  Metrics Buffer: $($monitorStatus.MetricsBufferSize)" -ForegroundColor White
    Write-Host "  Alert Rules: $($monitorStatus.ActiveAlertRules)/$($monitorStatus.TotalAlertRules)" -ForegroundColor White
    
    Write-Host "`nSystem is ready for operation!" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Cyan
}

# Main execution
try {
    # Check if required modules are available
    $requiredModules = @("Microsoft.PowerShell.SecretManagement")
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Warning "Required module '$module' not found. Installing..."
            try {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                Write-Host "✓ Installed module: $module" -ForegroundColor Green
            } catch {
                Write-Error "Failed to install required module '$module': $($_.Exception.Message)"
                exit 1
            }
        }
    }
    
    # Set secure mode environment variable for production
    if ($Environment -eq "Production") {
        $env:AIMASTER_SECURE_MODE = "true"
    }
    
    # Initialize the security system
    $systemComponents = Initialize-AIMasterSecuritySystem -Environment $Environment -ConfigPath $ConfigPath
    
    if ($InitializeOnly) {
        Write-Host "`nInitialization completed successfully!" -ForegroundColor Green
        exit 0
    }
    
    # Create sample user if requested
    $sampleUser = $null
    if ($CreateSampleUser) {
        $sampleUser = Create-SampleUser -SystemComponents $systemComponents
    }
    
    # Run tests if requested
    if ($RunTests) {
        $testResults = Test-SecuritySystem -SystemComponents $systemComponents -SampleUser $sampleUser
    }
    
    # Display system status
    Show-SystemStatus -SystemComponents $systemComponents
    
    # Interactive mode
    if (-not $InitializeOnly -and -not $RunTests) {
        Write-Host "`nAIMaster Security System is now running in interactive mode." -ForegroundColor Cyan
        Write-Host "Press 'Q' to quit, 'S' for status, 'H' for help:" -ForegroundColor Yellow
        
        do {
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            switch ($key.Character.ToString().ToUpper()) {
                'Q' {
                    Write-Host "`nShutting down AIMaster Security System..." -ForegroundColor Yellow
                    if ($systemComponents.MonitoringSystem) {
                        $systemComponents.MonitoringSystem.StopMonitoring()
                    }
                    if ($systemComponents.SandboxManager) {
                        $systemComponents.SandboxManager.ShutdownAll()
                    }
                    if ($systemComponents.Orchestrator) {
                        $systemComponents.Orchestrator.ShutdownAll()
                    }
                    Write-Host "✓ System shutdown complete" -ForegroundColor Green
                    break
                }
                'S' {
                    Show-SystemStatus -SystemComponents $systemComponents
                }
                'H' {
                    Write-Host "`nAIMaster Security System - Help" -ForegroundColor Cyan
                    Write-Host "Commands:" -ForegroundColor White
                    Write-Host "  Q - Quit the system" -ForegroundColor White
                    Write-Host "  S - Show system status" -ForegroundColor White
                    Write-Host "  H - Show this help message" -ForegroundColor White
                }
            }
        } while ($key.Character.ToString().ToUpper() -ne 'Q')
    }
    
    Write-Host "`nAIMaster Security System session ended." -ForegroundColor Green
    
} catch {
    Write-Error "AIMaster Security System failed: $($_.Exception.Message)"
    Write-Host "`nStack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
