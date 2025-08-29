# AIMaster Audit and Monitoring System
# Comprehensive logging, monitoring, and audit capabilities for security and compliance

#Requires -Version 7.0

using namespace System.Diagnostics
using namespace System.Collections.Concurrent
using namespace System.Threading.Tasks

[CmdletBinding()]
param()

# Import required modules
Import-Module -Name (Join-Path $PSScriptRoot "../Config/SecurityConfiguration.psm1") -Force
Import-Module -Name (Join-Path $PSScriptRoot "../Auth/AuthenticationFramework.psm1") -Force

# Audit event classes
class AuditEvent {
    [string]$EventId
    [datetime]$Timestamp
    [string]$EventType
    [string]$Category
    [string]$Source
    [string]$UserId
    [string]$Username
    [string]$SessionId
    [string]$Action
    [string]$Resource
    [string]$Result
    [string]$Message
    [hashtable]$Details
    [string]$IpAddress
    [string]$UserAgent
    [string]$Severity
    [hashtable]$Context
    
    AuditEvent([string]$eventType, [string]$category, [string]$action, [string]$message) {
        $this.EventId = [System.Guid]::NewGuid().ToString()
        $this.Timestamp = Get-Date
        $this.EventType = $eventType
        $this.Category = $category
        $this.Action = $action
        $this.Message = $message
        $this.Details = @{}
        $this.Context = @{}
        $this.Severity = "Information"
        $this.Result = "Unknown"
    }
    
    [hashtable] ToHashtable() {
        return @{
            EventId = $this.EventId
            Timestamp = $this.Timestamp
            EventType = $this.EventType
            Category = $this.Category
            Source = $this.Source
            UserId = $this.UserId
            Username = $this.Username
            SessionId = $this.SessionId
            Action = $this.Action
            Resource = $this.Resource
            Result = $this.Result
            Message = $this.Message
            Details = $this.Details
            IpAddress = $this.IpAddress
            UserAgent = $this.UserAgent
            Severity = $this.Severity
            Context = $this.Context
        }
    }
    
    [string] ToJson() {
        return $this.ToHashtable() | ConvertTo-Json -Depth 10 -Compress
    }
    
    [string] ToLogFormat() {
        return "[$($this.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))] [$($this.Severity)] [$($this.Category)] [$($this.Action)] $($this.Message) | User: $($this.Username) | Resource: $($this.Resource) | Result: $($this.Result)"
    }
}

class SecurityMetric {
    [string]$MetricId
    [datetime]$Timestamp
    [string]$MetricName
    [string]$Category
    [double]$Value
    [string]$Unit
    [hashtable]$Tags
    [string]$Source
    
    SecurityMetric([string]$metricName, [string]$category, [double]$value, [string]$unit = "count") {
        $this.MetricId = [System.Guid]::NewGuid().ToString()
        $this.Timestamp = Get-Date
        $this.MetricName = $metricName
        $this.Category = $category
        $this.Value = $value
        $this.Unit = $unit
        $this.Tags = @{}
    }
    
    [hashtable] ToHashtable() {
        return @{
            MetricId = $this.MetricId
            Timestamp = $this.Timestamp
            MetricName = $this.MetricName
            Category = $this.Category
            Value = $this.Value
            Unit = $this.Unit
            Tags = $this.Tags
            Source = $this.Source
        }
    }
}

class AlertRule {
    [string]$RuleId
    [string]$RuleName
    [string]$Description
    [string]$MetricName
    [string]$Condition
    [double]$Threshold
    [int]$WindowMinutes
    [string]$Severity
    [string[]]$Recipients
    [bool]$IsEnabled
    [datetime]$CreatedAt
    [datetime]$LastTriggered
    [int]$TriggerCount
    
    AlertRule([string]$ruleName, [string]$metricName, [string]$condition, [double]$threshold) {
        $this.RuleId = [System.Guid]::NewGuid().ToString()
        $this.RuleName = $ruleName
        $this.MetricName = $metricName
        $this.Condition = $condition
        $this.Threshold = $threshold
        $this.WindowMinutes = 5
        $this.Severity = "Warning"
        $this.Recipients = @()
        $this.IsEnabled = $true
        $this.CreatedAt = Get-Date
        $this.TriggerCount = 0
    }
    
    [bool] EvaluateCondition([double]$currentValue) {
        if (-not $this.IsEnabled) {
            return $false
        }
        
        switch ($this.Condition.ToLower()) {
            "greater_than" { return $currentValue -gt $this.Threshold }
            "less_than" { return $currentValue -lt $this.Threshold }
            "equals" { return $currentValue -eq $this.Threshold }
            "not_equals" { return $currentValue -ne $this.Threshold }
            "greater_than_or_equal" { return $currentValue -ge $this.Threshold }
            "less_than_or_equal" { return $currentValue -le $this.Threshold }
            default { return $false }
        }
    }
    
    [void] RecordTrigger() {
        $this.LastTriggered = Get-Date
        $this.TriggerCount++
    }
}

class LogRotationManager {
    [string]$LogDirectory
    [long]$MaxFileSizeBytes
    [int]$MaxFileCount
    [int]$RetentionDays
    
    LogRotationManager([string]$logDirectory) {
        $this.LogDirectory = $logDirectory
        $this.MaxFileSizeBytes = 100MB
        $this.MaxFileCount = 10
        $this.RetentionDays = 90
    }
    
    [void] RotateLogFile([string]$logFilePath) {
        if (-not (Test-Path $logFilePath)) {
            return
        }
        
        $fileInfo = Get-Item $logFilePath
        if ($fileInfo.Length -gt $this.MaxFileSizeBytes) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $directory = Split-Path $logFilePath -Parent
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($logFilePath)
            $extension = [System.IO.Path]::GetExtension($logFilePath)
            
            $rotatedFileName = "$baseName-$timestamp$extension"
            $rotatedFilePath = Join-Path $directory $rotatedFileName
            
            Move-Item $logFilePath $rotatedFilePath -Force
            
            # Compress rotated log
            try {
                Compress-Archive -Path $rotatedFilePath -DestinationPath "$rotatedFilePath.zip" -Force
                Remove-Item $rotatedFilePath -Force
            } catch {
                # If compression fails, keep the original file
            }
            
            $this.CleanupOldLogs($directory, $baseName, $extension)
        }
    }
    
    [void] CleanupOldLogs([string]$directory, [string]$baseName, [string]$extension) {
        # Remove old rotated logs beyond retention policy
        $cutoffDate = (Get-Date).AddDays(-$this.RetentionDays)
        $pattern = "$baseName-*$extension*"
        
        Get-ChildItem -Path $directory -Filter $pattern | Where-Object {
            $_.CreationTime -lt $cutoffDate
        } | Remove-Item -Force
        
        # Remove excess log files if we have too many
        $logFiles = Get-ChildItem -Path $directory -Filter $pattern | Sort-Object CreationTime -Descending
        if ($logFiles.Count -gt $this.MaxFileCount) {
            $filesToRemove = $logFiles | Select-Object -Skip $this.MaxFileCount
            $filesToRemove | Remove-Item -Force
        }
    }
}

# Main audit and monitoring system
class AuditAndMonitoringSystem {
    [SecurityManager]$SecurityManager
    [AuthenticationManager]$AuthenticationManager
    [System.Collections.Concurrent.ConcurrentQueue[AuditEvent]]$EventQueue
    [System.Collections.Concurrent.ConcurrentDictionary[string,SecurityMetric]]$MetricsBuffer
    [hashtable]$AlertRules
    [hashtable]$LogWriters
    [LogRotationManager]$LogRotationManager
    [string]$MonitoringRoot
    [string]$LogsRoot
    [string]$MetricsRoot
    [string]$AlertsRoot
    [bool]$IsRunning
    [System.Threading.Timer]$ProcessingTimer
    [System.Threading.Timer]$MetricsTimer
    [System.Threading.Timer]$AlertsTimer
    
    AuditAndMonitoringSystem([SecurityManager]$securityManager, [AuthenticationManager]$authManager) {
        $this.SecurityManager = $securityManager
        $this.AuthenticationManager = $authManager
        $this.EventQueue = [System.Collections.Concurrent.ConcurrentQueue[AuditEvent]]::new()
        $this.MetricsBuffer = [System.Collections.Concurrent.ConcurrentDictionary[string,SecurityMetric]]::new()
        $this.AlertRules = @{}
        $this.LogWriters = @{}
        
        $this.MonitoringRoot = Join-Path $this.SecurityManager.Config.GetSecureRoot() "Monitoring"
        $this.LogsRoot = Join-Path $this.MonitoringRoot "Logs"
        $this.MetricsRoot = Join-Path $this.MonitoringRoot "Metrics"
        $this.AlertsRoot = Join-Path $this.MonitoringRoot "Alerts"
        
        $this.InitializeMonitoringEnvironment()
        $this.CreateDefaultAlertRules()
        $this.StartMonitoring()
        
        $this.SecurityManager.LogSecurityEvent("AuditAndMonitoringSystem initialized", "Information")
    }
    
    [void] InitializeMonitoringEnvironment() {
        $directories = @(
            $this.MonitoringRoot,
            $this.LogsRoot,
            $this.MetricsRoot,
            $this.AlertsRoot,
            (Join-Path $this.LogsRoot "Security"),
            (Join-Path $this.LogsRoot "Application"),
            (Join-Path $this.LogsRoot "System"),
            (Join-Path $this.LogsRoot "Audit"),
            (Join-Path $this.MetricsRoot "Performance"),
            (Join-Path $this.MetricsRoot "Security"),
            (Join-Path $this.AlertsRoot "Active"),
            (Join-Path $this.AlertsRoot "History")
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                
                # Set secure permissions
                if ($IsWindows) {
                    $acl = Get-Acl $dir
                    $acl.SetAccessRuleProtection($true, $false)
                    
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $currentUser,
                        "FullControl",
                        "ContainerInherit,ObjectInherit",
                        "None",
                        "Allow"
                    )
                    $acl.SetAccessRule($accessRule)
                    Set-Acl -Path $dir -AclObject $acl
                } else {
                    chmod 700 $dir
                }
            }
        }
        
        $this.LogRotationManager = [LogRotationManager]::new($this.LogsRoot)
        
        # Initialize log writers
        $this.LogWriters["Security"] = Join-Path $this.LogsRoot "Security/security.log"
        $this.LogWriters["Application"] = Join-Path $this.LogsRoot "Application/application.log"
        $this.LogWriters["System"] = Join-Path $this.LogsRoot "System/system.log"
        $this.LogWriters["Audit"] = Join-Path $this.LogsRoot "Audit/audit.log"
    }
    
    [void] CreateDefaultAlertRules() {
        # Failed login attempts
        $failedLoginRule = [AlertRule]::new("High Failed Login Attempts", "security.failed_logins", "greater_than", 5)
        $failedLoginRule.Description = "Alert when failed login attempts exceed threshold"
        $failedLoginRule.WindowMinutes = 10
        $failedLoginRule.Severity = "Critical"
        $this.AlertRules[$failedLoginRule.RuleId] = $failedLoginRule
        
        # Suspicious activity
        $suspiciousActivityRule = [AlertRule]::new("Suspicious Activity Detected", "security.suspicious_activity", "greater_than", 0)
        $suspiciousActivityRule.Description = "Alert on any suspicious activity detection"
        $suspiciousActivityRule.Severity = "High"
        $this.AlertRules[$suspiciousActivityRule.RuleId] = $suspiciousActivityRule
        
        # High resource usage
        $resourceRule = [AlertRule]::new("High Resource Usage", "system.cpu_usage", "greater_than", 90)
        $resourceRule.Description = "Alert when CPU usage exceeds 90%"
        $resourceRule.WindowMinutes = 5
        $resourceRule.Severity = "Warning"
        $this.AlertRules[$resourceRule.RuleId] = $resourceRule
        
        # Deployment failures
        $deploymentRule = [AlertRule]::new("Deployment Failures", "deployment.failures", "greater_than", 0)
        $deploymentRule.Description = "Alert on deployment failures"
        $deploymentRule.Severity = "High"
        $this.AlertRules[$deploymentRule.RuleId] = $deploymentRule
    }
    
    [void] StartMonitoring() {
        $this.IsRunning = $true
        
        # Start event processing timer (every 10 seconds)
        $processEvents = {
            try {
                $this.ProcessEventQueue()
            } catch {
                # Handle timer errors silently to prevent system instability
            }
        }
        $this.ProcessingTimer = New-Object System.Threading.Timer($processEvents, $null, 1000, 10000)
        
        # Start metrics collection timer (every 30 seconds)
        $collectMetrics = {
            try {
                $this.CollectSystemMetrics()
                $this.ProcessMetrics()
            } catch {
                # Handle timer errors silently
            }
        }
        $this.MetricsTimer = New-Object System.Threading.Timer($collectMetrics, $null, 5000, 30000)
        
        # Start alerts evaluation timer (every 60 seconds)
        $evaluateAlerts = {
            try {
                $this.EvaluateAlertRules()
            } catch {
                # Handle timer errors silently
            }
        }
        $this.AlertsTimer = New-Object System.Threading.Timer($evaluateAlerts, $null, 10000, 60000)
    }
    
    [void] StopMonitoring() {
        $this.IsRunning = $false
        
        if ($this.ProcessingTimer) {
            $this.ProcessingTimer.Dispose()
        }
        
        if ($this.MetricsTimer) {
            $this.MetricsTimer.Dispose()
        }
        
        if ($this.AlertsTimer) {
            $this.AlertsTimer.Dispose()
        }
        
        # Process remaining events
        $this.ProcessEventQueue()
        $this.ProcessMetrics()
    }
    
    [void] LogAuditEvent([AuditEvent]$auditEvent) {
        # Enrich event with additional context
        if ($auditEvent.SessionId -and $this.AuthenticationManager) {
            try {
                $user = $this.AuthenticationManager.GetUserFromToken($auditEvent.SessionId)
                if ($user) {
                    $auditEvent.UserId = $user.UserId
                    $auditEvent.Username = $user.Username
                }
            } catch {
                # Token might be invalid, continue without user info
            }
        }
        
        $auditEvent.Source = "AIMaster"
        
        # Add to processing queue
        $this.EventQueue.Enqueue($auditEvent)
        
        # For critical events, process immediately
        if ($auditEvent.Severity -eq "Critical" -or $auditEvent.Severity -eq "Error") {
            $this.ProcessEventQueue()
        }
    }
    
    [void] LogSecurityEvent([string]$action, [string]$message, [string]$severity = "Information", [hashtable]$details = @{}) {
        $event = [AuditEvent]::new("Security", "Security", $action, $message)
        $event.Severity = $severity
        $event.Details = $details
        $this.LogAuditEvent($event)
    }
    
    [void] LogApplicationEvent([string]$action, [string]$message, [string]$severity = "Information", [hashtable]$details = @{}) {
        $event = [AuditEvent]::new("Application", "Application", $action, $message)
        $event.Severity = $severity
        $event.Details = $details
        $this.LogAuditEvent($event)
    }
    
    [void] LogSystemEvent([string]$action, [string]$message, [string]$severity = "Information", [hashtable]$details = @{}) {
        $event = [AuditEvent]::new("System", "System", $action, $message)
        $event.Severity = $severity
        $event.Details = $details
        $this.LogAuditEvent($event)
    }
    
    [void] RecordMetric([string]$metricName, [string]$category, [double]$value, [string]$unit = "count", [hashtable]$tags = @{}) {
        $metric = [SecurityMetric]::new($metricName, $category, $value, $unit)
        $metric.Tags = $tags
        $metric.Source = "AIMaster"
        
        $this.MetricsBuffer.TryAdd($metric.MetricId, $metric)
    }
    
    [void] ProcessEventQueue() {
        $processedEvents = 0
        $maxBatchSize = 100
        
        while ($this.EventQueue.TryDequeue([ref]$null) -and $processedEvents -lt $maxBatchSize) {
            $event = $null
            if ($this.EventQueue.TryDequeue([ref]$event)) {
                try {
                    $this.WriteEventToLog($event)
                    $this.UpdateSecurityMetrics($event)
                    $processedEvents++
                } catch {
                    # Log processing error but continue
                    Write-Warning "Failed to process audit event: $($_.Exception.Message)"
                }
            }
        }
        
        # Rotate logs if needed
        foreach ($logFile in $this.LogWriters.Values) {
            $this.LogRotationManager.RotateLogFile($logFile)
        }
    }
    
    [void] WriteEventToLog([AuditEvent]$event) {
        $logFile = $this.LogWriters[$event.Category]
        if (-not $logFile) {
            $logFile = $this.LogWriters["Application"]
        }
        
        $logEntry = $event.ToLogFormat()
        
        # Ensure log directory exists
        $logDir = Split-Path $logFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        
        # Write to log file (thread-safe)
        $mutex = New-Object System.Threading.Mutex($false, "AIMasterLogMutex")
        try {
            $mutex.WaitOne() | Out-Null
            Add-Content -Path $logFile -Value $logEntry -Force -Encoding UTF8
            
            # Also write JSON format for structured logging
            $jsonLogFile = $logFile -replace "\.log$", ".json.log"
            Add-Content -Path $jsonLogFile -Value $event.ToJson() -Force -Encoding UTF8
        } finally {
            $mutex.ReleaseMutex()
        }
    }
    
    [void] UpdateSecurityMetrics([AuditEvent]$event) {
        # Update various security metrics based on the event
        switch ($event.Category) {\n            \"Security\" {\n                if ($event.Action -eq \"Login\" -and $event.Result -eq \"Failed\") {\n                    $this.RecordMetric(\"security.failed_logins\", \"Security\", 1)\n                }\n                \n                if ($event.Action -eq \"Login\" -and $event.Result -eq \"Success\") {\n                    $this.RecordMetric(\"security.successful_logins\", \"Security\", 1)\n                }\n                \n                if ($event.Severity -eq \"Critical\" -or $event.Severity -eq \"Error\") {\n                    $this.RecordMetric(\"security.security_incidents\", \"Security\", 1)\n                }\n            }\n            \n            \"Application\" {\n                if ($event.Severity -eq \"Error\") {\n                    $this.RecordMetric(\"application.errors\", \"Application\", 1)\n                }\n                \n                if ($event.Action -eq \"Deployment\" -and $event.Result -eq \"Failed\") {\n                    $this.RecordMetric(\"deployment.failures\", \"Deployment\", 1)\n                }\n            }\n        }\n        \n        # General event count\n        $this.RecordMetric(\"events.total\", \"General\", 1, \"count\", @{Category = $event.Category; Severity = $event.Severity})\n    }\n    \n    [void] CollectSystemMetrics() {\n        try {\n            # CPU Usage\n            if ($IsWindows) {\n                $cpuUsage = (Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average\n                if ($cpuUsage) {\n                    $this.RecordMetric(\"system.cpu_usage\", \"System\", $cpuUsage, \"percent\")\n                }\n                \n                # Memory Usage\n                $totalMemory = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory\n                $availableMemory = (Get-WmiObject -Class Win32_OperatingSystem).FreePhysicalMemory * 1KB\n                $usedMemory = $totalMemory - $availableMemory\n                $memoryUsagePercent = ($usedMemory / $totalMemory) * 100\n                $this.RecordMetric(\"system.memory_usage\", \"System\", $memoryUsagePercent, \"percent\")\n            } else {\n                # Unix-like systems\n                try {\n                    $loadAvg = (Get-Content \"/proc/loadavg\" -ErrorAction SilentlyContinue).Split(' ')[0]\n                    if ($loadAvg) {\n                        $this.RecordMetric(\"system.load_average\", \"System\", [double]$loadAvg, \"ratio\")\n                    }\n                } catch {\n                    # Load average not available\n                }\n                \n                try {\n                    $memInfo = Get-Content \"/proc/meminfo\" -ErrorAction SilentlyContinue\n                    if ($memInfo) {\n                        $totalMem = ($memInfo | Where-Object { $_ -match \"MemTotal\" }).Split()[1]\n                        $availableMem = ($memInfo | Where-Object { $_ -match \"MemAvailable\" }).Split()[1]\n                        \n                        if ($totalMem -and $availableMem) {\n                            $memoryUsagePercent = ((([int]$totalMem - [int]$availableMem) / [int]$totalMem) * 100)\n                            $this.RecordMetric(\"system.memory_usage\", \"System\", $memoryUsagePercent, \"percent\")\n                        }\n                    }\n                } catch {\n                    # Memory info not available\n                }\n            }\n            \n            # Disk Usage\n            $drives = Get-PSDrive -PSProvider FileSystem\n            foreach ($drive in $drives) {\n                try {\n                    if ($drive.Used -and $drive.Free) {\n                        $total = $drive.Used + $drive.Free\n                        $usagePercent = ($drive.Used / $total) * 100\n                        $this.RecordMetric(\"system.disk_usage\", \"System\", $usagePercent, \"percent\", @{Drive = $drive.Name})\n                    }\n                } catch {\n                    # Drive info not available\n                }\n            }\n            \n        } catch {\n            # System metrics collection error - log but continue\n            $this.LogSystemEvent(\"MetricsCollection\", \"Failed to collect system metrics: $($_.Exception.Message)\", \"Warning\")\n        }\n    }\n    \n    [void] ProcessMetrics() {\n        $processedMetrics = 0\n        $maxBatchSize = 100\n        \n        $metricsToProcess = @()\n        foreach ($metricId in $this.MetricsBuffer.Keys) {\n            if ($processedMetrics -ge $maxBatchSize) {\n                break\n            }\n            \n            $metric = $null\n            if ($this.MetricsBuffer.TryRemove($metricId, [ref]$metric)) {\n                $metricsToProcess += $metric\n                $processedMetrics++\n            }\n        }\n        \n        if ($metricsToProcess.Count -gt 0) {\n            $this.WriteMetricsToFile($metricsToProcess)\n        }\n    }\n    \n    [void] WriteMetricsToFile([SecurityMetric[]]$metrics) {\n        $metricsFile = Join-Path $this.MetricsRoot \"metrics-$(Get-Date -Format 'yyyy-MM-dd').json\"\n        \n        $mutex = New-Object System.Threading.Mutex($false, \"AIMasterMetricsMutex\")\n        try {\n            $mutex.WaitOne() | Out-Null\n            \n            foreach ($metric in $metrics) {\n                $metricJson = $metric.ToHashtable() | ConvertTo-Json -Depth 5 -Compress\n                Add-Content -Path $metricsFile -Value $metricJson -Force -Encoding UTF8\n            }\n        } finally {\n            $mutex.ReleaseMutex()\n        }\n        \n        # Rotate metrics file if it gets too large\n        $this.LogRotationManager.RotateLogFile($metricsFile)\n    }\n    \n    [void] EvaluateAlertRules() {\n        foreach ($rule in $this.AlertRules.Values) {\n            try {\n                if (-not $rule.IsEnabled) {\n                    continue\n                }\n                \n                # Get recent metrics for this rule\n                $recentMetrics = $this.GetRecentMetrics($rule.MetricName, $rule.WindowMinutes)\n                \n                if ($recentMetrics.Count -gt 0) {\n                    $currentValue = ($recentMetrics | Measure-Object -Property Value -Sum).Sum\n                    \n                    if ($rule.EvaluateCondition($currentValue)) {\n                        $this.TriggerAlert($rule, $currentValue, $recentMetrics)\n                    }\n                }\n            } catch {\n                $this.LogSystemEvent(\"AlertEvaluation\", \"Failed to evaluate alert rule $($rule.RuleName): $($_.Exception.Message)\", \"Warning\")\n            }\n        }\n    }\n    \n    [SecurityMetric[]] GetRecentMetrics([string]$metricName, [int]$windowMinutes) {\n        $cutoffTime = (Get-Date).AddMinutes(-$windowMinutes)\n        $results = @()\n        \n        # Get from current buffer\n        foreach ($metric in $this.MetricsBuffer.Values) {\n            if ($metric.MetricName -eq $metricName -and $metric.Timestamp -gt $cutoffTime) {\n                $results += $metric\n            }\n        }\n        \n        return $results\n    }\n    \n    [void] TriggerAlert([AlertRule]$rule, [double]$currentValue, [SecurityMetric[]]$triggeringMetrics) {\n        $rule.RecordTrigger()\n        \n        $alert = @{\n            AlertId = [System.Guid]::NewGuid().ToString()\n            RuleId = $rule.RuleId\n            RuleName = $rule.RuleName\n            Timestamp = Get-Date\n            Severity = $rule.Severity\n            MetricName = $rule.MetricName\n            CurrentValue = $currentValue\n            Threshold = $rule.Threshold\n            Condition = $rule.Condition\n            Message = \"Alert triggered: $($rule.RuleName) - Current value: $currentValue, Threshold: $($rule.Threshold)\"\n            TriggeringMetrics = $triggeringMetrics\n        }\n        \n        # Write alert to file\n        $alertsFile = Join-Path $this.AlertsRoot \"Active/alerts-$(Get-Date -Format 'yyyy-MM-dd').json\"\n        $alertJson = $alert | ConvertTo-Json -Depth 10 -Compress\n        Add-Content -Path $alertsFile -Value $alertJson -Force -Encoding UTF8\n        \n        # Log alert as security event\n        $this.LogSecurityEvent(\"AlertTriggered\", $alert.Message, $rule.Severity, @{\n            AlertId = $alert.AlertId\n            RuleName = $rule.RuleName\n            MetricName = $rule.MetricName\n            CurrentValue = $currentValue\n            Threshold = $rule.Threshold\n        })\n        \n        # Send notifications (placeholder - implement actual notification logic)\n        $this.SendAlertNotifications($alert, $rule)\n    }\n    \n    [void] SendAlertNotifications([hashtable]$alert, [AlertRule]$rule) {\n        # Placeholder for alert notification implementation\n        # In a real implementation, you would send emails, SMS, Slack messages, etc.\n        \n        foreach ($recipient in $rule.Recipients) {\n            try {\n                # Log notification attempt\n                $this.LogSystemEvent(\"AlertNotification\", \"Alert notification sent to $recipient for $($rule.RuleName)\", \"Information\")\n            } catch {\n                $this.LogSystemEvent(\"AlertNotification\", \"Failed to send alert notification to $recipient: $($_.Exception.Message)\", \"Warning\")\n            }\n        }\n    }\n    \n    [hashtable[]] GetAuditEvents([string]$tokenId, [datetime]$startTime, [datetime]$endTime, [string]$category = \"\", [int]$limit = 1000) {\n        # Validate user authorization\n        if (-not $this.AuthenticationManager.AuthorizeUserAction($tokenId, \"audit.read\")) {\n            throw \"Access denied: insufficient permissions\"\n        }\n        \n        $results = @()\n        \n        # Search through log files\n        $logFiles = Get-ChildItem -Path $this.LogsRoot -Filter \"*.json.log\" -Recurse\n        \n        foreach ($logFile in $logFiles) {\n            if ($results.Count -ge $limit) {\n                break\n            }\n            \n            try {\n                $logContent = Get-Content $logFile.FullName\n                foreach ($line in $logContent) {\n                    if ([string]::IsNullOrWhiteSpace($line)) {\n                        continue\n                    }\n                    \n                    try {\n                        $event = $line | ConvertFrom-Json\n                        $eventTime = [datetime]$event.Timestamp\n                        \n                        if ($eventTime -ge $startTime -and $eventTime -le $endTime) {\n                            if ([string]::IsNullOrEmpty($category) -or $event.Category -eq $category) {\n                                $results += $event\n                                \n                                if ($results.Count -ge $limit) {\n                                    break\n                                }\n                            }\n                        }\n                    } catch {\n                        # Skip malformed JSON lines\n                    }\n                }\n            } catch {\n                # Skip files that can't be read\n            }\n        }\n        \n        return $results | Sort-Object Timestamp -Descending\n    }\n    \n    [hashtable[]] GetSecurityMetrics([string]$tokenId, [datetime]$startTime, [datetime]$endTime, [string]$metricName = \"\", [int]$limit = 1000) {\n        # Validate user authorization\n        if (-not $this.AuthenticationManager.AuthorizeUserAction($tokenId, \"metrics.read\")) {\n            throw \"Access denied: insufficient permissions\"\n        }\n        \n        $results = @()\n        \n        # Search through metrics files\n        $metricsFiles = Get-ChildItem -Path $this.MetricsRoot -Filter \"*.json\" -Recurse\n        \n        foreach ($metricsFile in $metricsFiles) {\n            if ($results.Count -ge $limit) {\n                break\n            }\n            \n            try {\n                $metricsContent = Get-Content $metricsFile.FullName\n                foreach ($line in $metricsContent) {\n                    if ([string]::IsNullOrWhiteSpace($line)) {\n                        continue\n                    }\n                    \n                    try {\n                        $metric = $line | ConvertFrom-Json\n                        $metricTime = [datetime]$metric.Timestamp\n                        \n                        if ($metricTime -ge $startTime -and $metricTime -le $endTime) {\n                            if ([string]::IsNullOrEmpty($metricName) -or $metric.MetricName -eq $metricName) {\n                                $results += $metric\n                                \n                                if ($results.Count -ge $limit) {\n                                    break\n                                }\n                            }\n                        }\n                    } catch {\n                        # Skip malformed JSON lines\n                    }\n                }\n            } catch {\n                # Skip files that can't be read\n            }\n        }\n        \n        return $results | Sort-Object Timestamp -Descending\n    }\n    \n    [hashtable] GetSystemStatus() {\n        return @{\n            IsRunning = $this.IsRunning\n            EventQueueSize = $this.EventQueue.Count\n            MetricsBufferSize = $this.MetricsBuffer.Count\n            ActiveAlertRules = ($this.AlertRules.Values | Where-Object { $_.IsEnabled }).Count\n            TotalAlertRules = $this.AlertRules.Count\n            LogsDirectory = $this.LogsRoot\n            MetricsDirectory = $this.MetricsRoot\n            AlertsDirectory = $this.AlertsRoot\n        }\n    }\n}\n\n# Export functions\nfunction New-AuditAndMonitoringSystem {\n    <#\n    .SYNOPSIS\n    Creates a new audit and monitoring system instance.\n    \n    .DESCRIPTION\n    Initializes a comprehensive audit and monitoring system with logging,\n    metrics collection, alerting, and security event tracking.\n    \n    .PARAMETER SecurityManager\n    The security manager instance to use.\n    \n    .PARAMETER AuthenticationManager\n    The authentication manager instance to use.\n    \n    .EXAMPLE\n    $monitoringSystem = New-AuditAndMonitoringSystem -SecurityManager $securityManager -AuthenticationManager $authManager\n    #>\n    [CmdletBinding()]\n    param(\n        [Parameter(Mandatory = $true)]\n        [SecurityManager]$SecurityManager,\n        \n        [Parameter(Mandatory = $true)]\n        [AuthenticationManager]$AuthenticationManager\n    )\n    \n    try {\n        return [AuditAndMonitoringSystem]::new($SecurityManager, $AuthenticationManager)\n    } catch {\n        Write-Error \"Failed to create audit and monitoring system: $($_.Exception.Message)\"\n        throw\n    }\n}\n\nfunction Write-AuditEvent {\n    <#\n    .SYNOPSIS\n    Writes an audit event to the monitoring system.\n    \n    .DESCRIPTION\n    Logs a security, application, or system audit event for compliance and monitoring.\n    \n    .PARAMETER MonitoringSystem\n    The monitoring system instance.\n    \n    .PARAMETER EventType\n    The type of event (Security, Application, System).\n    \n    .PARAMETER Category\n    The event category.\n    \n    .PARAMETER Action\n    The action being audited.\n    \n    .PARAMETER Message\n    The audit message.\n    \n    .PARAMETER Severity\n    The event severity level.\n    \n    .PARAMETER Details\n    Additional event details.\n    \n    .EXAMPLE\n    Write-AuditEvent -MonitoringSystem $monitor -EventType \"Security\" -Category \"Authentication\" -Action \"Login\" -Message \"User login attempt\" -Severity \"Information\"\n    #>\n    [CmdletBinding()]\n    param(\n        [Parameter(Mandatory = $true)]\n        [AuditAndMonitoringSystem]$MonitoringSystem,\n        \n        [Parameter(Mandatory = $true)]\n        [string]$EventType,\n        \n        [Parameter(Mandatory = $true)]\n        [string]$Category,\n        \n        [Parameter(Mandatory = $true)]\n        [string]$Action,\n        \n        [Parameter(Mandatory = $true)]\n        [string]$Message,\n        \n        [Parameter(Mandatory = $false)]\n        [string]$Severity = \"Information\",\n        \n        [Parameter(Mandatory = $false)]\n        [hashtable]$Details = @{}\n    )\n    \n    try {\n        $event = [AuditEvent]::new($EventType, $Category, $Action, $Message)\n        $event.Severity = $Severity\n        $event.Details = $Details\n        \n        $MonitoringSystem.LogAuditEvent($event)\n    } catch {\n        Write-Error \"Failed to write audit event: $($_.Exception.Message)\"\n        throw\n    }\n}\n\nfunction Get-AuditTrail {\n    <#\n    .SYNOPSIS\n    Retrieves audit events for analysis.\n    \n    .DESCRIPTION\n    Queries the audit trail for events within a specified time range and criteria.\n    \n    .PARAMETER MonitoringSystem\n    The monitoring system instance.\n    \n    .PARAMETER TokenId\n    Authentication token ID.\n    \n    .PARAMETER StartTime\n    Start time for the query.\n    \n    .PARAMETER EndTime\n    End time for the query.\n    \n    .PARAMETER Category\n    Optional category filter.\n    \n    .PARAMETER Limit\n    Maximum number of events to return.\n    \n    .EXAMPLE\n    $events = Get-AuditTrail -MonitoringSystem $monitor -TokenId $token.TokenId -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date)\n    #>\n    [CmdletBinding()]\n    param(\n        [Parameter(Mandatory = $true)]\n        [AuditAndMonitoringSystem]$MonitoringSystem,\n        \n        [Parameter(Mandatory = $true)]\n        [string]$TokenId,\n        \n        [Parameter(Mandatory = $true)]\n        [datetime]$StartTime,\n        \n        [Parameter(Mandatory = $true)]\n        [datetime]$EndTime,\n        \n        [Parameter(Mandatory = $false)]\n        [string]$Category = \"\",\n        \n        [Parameter(Mandatory = $false)]\n        [int]$Limit = 1000\n    )\n    \n    try {\n        return $MonitoringSystem.GetAuditEvents($TokenId, $StartTime, $EndTime, $Category, $Limit)\n    } catch {\n        Write-Error \"Failed to retrieve audit trail: $($_.Exception.Message)\"\n        throw\n    }\n}\n\nfunction Get-SecurityMetrics {\n    <#\n    .SYNOPSIS\n    Retrieves security metrics for analysis.\n    \n    .DESCRIPTION\n    Queries security metrics for performance and security monitoring.\n    \n    .PARAMETER MonitoringSystem\n    The monitoring system instance.\n    \n    .PARAMETER TokenId\n    Authentication token ID.\n    \n    .PARAMETER StartTime\n    Start time for the query.\n    \n    .PARAMETER EndTime\n    End time for the query.\n    \n    .PARAMETER MetricName\n    Optional metric name filter.\n    \n    .PARAMETER Limit\n    Maximum number of metrics to return.\n    \n    .EXAMPLE\n    $metrics = Get-SecurityMetrics -MonitoringSystem $monitor -TokenId $token.TokenId -StartTime (Get-Date).AddHours(-1) -EndTime (Get-Date)\n    #>\n    [CmdletBinding()]\n    param(\n        [Parameter(Mandatory = $true)]\n        [AuditAndMonitoringSystem]$MonitoringSystem,\n        \n        [Parameter(Mandatory = $true)]\n        [string]$TokenId,\n        \n        [Parameter(Mandatory = $true)]\n        [datetime]$StartTime,\n        \n        [Parameter(Mandatory = $true)]\n        [datetime]$EndTime,\n        \n        [Parameter(Mandatory = $false)]\n        [string]$MetricName = \"\",\n        \n        [Parameter(Mandatory = $false)]\n        [int]$Limit = 1000\n    )\n    \n    try {\n        return $MonitoringSystem.GetSecurityMetrics($TokenId, $StartTime, $EndTime, $MetricName, $Limit)\n    } catch {\n        Write-Error \"Failed to retrieve security metrics: $($_.Exception.Message)\"\n        throw\n    }\n}\n\n# Export module members\nExport-ModuleMember -Function @(\n    'New-AuditAndMonitoringSystem',\n    'Write-AuditEvent',\n    'Get-AuditTrail',\n    'Get-SecurityMetrics'\n) -Variable @() -Cmdlet @() -Alias @()"
