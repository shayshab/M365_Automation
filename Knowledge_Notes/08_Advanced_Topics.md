# Advanced Topics

## Multi-Tenant Management

### Managing Multiple Tenants
```powershell
function Manage-MultipleTenants {
    $Tenants = @("tenant1.onmicrosoft.com", "tenant2.onmicrosoft.com")

    foreach ($Tenant in $Tenants) {
        Write-Host "Processing tenant: $Tenant" -ForegroundColor Green
        
        # Connect to tenant
        Connect-AzureAD -TenantId $Tenant
        
        # Apply consistent policies across tenants
        $Policy = @{
            DisplayName = "Standard Security Policy"
            Description = "Applied across all tenants"
            # Policy configuration
        }
        
        # Deploy policy
        Write-Host "Deploying policy to $Tenant" -ForegroundColor Green
        
        # Disconnect
        Disconnect-AzureAD
    }
}
```

### Cross-Tenant Collaboration
```powershell
function Setup-CrossTenantCollaboration {
    param(
        [string]$SourceTenant,
        [string]$TargetTenant,
        [string[]]$SharedApplications
    )
    
    # Configure B2B collaboration
    foreach ($App in $SharedApplications) {
        # Configure app sharing between tenants
        Write-Host "Configuring $App for cross-tenant access" -ForegroundColor Yellow
        
        # Add cross-tenant access policy
        $CrossTenantPolicy = @{
            "@odata.type" = "#microsoft.graph.crossTenantAccessPolicy"
            displayName = "Cross-tenant policy for $App"
            # Policy configuration
        }
        
        # Apply policy
        New-MgPolicyCrossTenantAccessPolicy -BodyParameter $CrossTenantPolicy
    }
}
```

## Advanced Security Implementations

### Zero Trust Architecture
```powershell
function Implement-ZeroTrust {
    # Configure device compliance
    $DeviceCompliancePolicy = @{
        "@odata.type" = "#microsoft.graph.windows10CompliancePolicy"
        displayName = "Zero Trust Device Compliance"
        requireHealthyDeviceReport = $true
        securityRequireTpm = $true
        storageRequireEncryption = $true
        passwordRequired = $true
        passwordMinimumLength = 12
        passwordRequiredType = "alphanumeric"
    }
    
    # Configure conditional access
    $CAPolicy = @{
        displayName = "Zero Trust Conditional Access"
        state = "Enabled"
        conditions = @{
            applications = @{includeApplications = @("All")}
            users = @{includeUsers = @("All")}
            devices = @{
                includeDevices = @("All")
                excludeDevices = @("Compliant")
            }
        }
        grantControls = @{
            operator = "AND"
            builtInControls = @("mfa", "compliantDevice")
        }
    }
    
    # Deploy policies
    New-MgDeviceManagementDeviceCompliancePolicy -BodyParameter $DeviceCompliancePolicy
    New-MgIdentityConditionalAccessPolicy -BodyParameter $CAPolicy
}
```

### Advanced Threat Protection
```powershell
function Configure-AdvancedThreatProtection {
    # Enable Microsoft Defender for Office 365
    $SafeAttachmentPolicy = @{
        Name = "Safe Attachments Policy"
        Action = "Block"
        Enable = $true
        Redirect = $false
    }
    
    $SafeLinkPolicy = @{
        Name = "Safe Links Policy"
        EnableSafeLinksForEmail = $true
        EnableSafeLinksForTeams = $true
        EnableSafeLinksForOffice = $true
    }
    
    # Configure policies
    New-SafeAttachmentPolicy @SafeAttachmentPolicy
    New-SafeLinksPolicy @SafeLinkPolicy
}
```

## Advanced Automation and Orchestration

### Workflow Automation
```powershell
function Start-UserOnboardingWorkflow {
    param(
        [string]$UserPrincipalName,
        [string]$Department,
        [string]$Manager,
        [string[]]$RequiredApplications
    )
    
    $WorkflowSteps = @(
        @{
            Name = "Create User Account"
            Function = {New-AzureADUser -UserPrincipalName $UserPrincipalName}
            RetryCount = 3
        },
        @{
            Name = "Assign Licenses"
            Function = {Set-AzureADUserLicense -UserPrincipalName $UserPrincipalName}
            RetryCount = 3
        },
        @{
            Name = "Add to Groups"
            Function = {Add-UserToDepartmentGroups -UserPrincipalName $UserPrincipalName -Department $Department}
            RetryCount = 2
        },
        @{
            Name = "Deploy Applications"
            Function = {Deploy-RequiredApplications -UserPrincipalName $UserPrincipalName -Applications $RequiredApplications}
            RetryCount = 5
        },
        @{
            Name = "Send Welcome Email"
            Function = {Send-WelcomeEmail -UserPrincipalName $UserPrincipalName -Manager $Manager}
            RetryCount = 1
        }
    )
    
    foreach ($Step in $WorkflowSteps) {
        $Attempt = 1
        $Success = $false
        
        do {
            try {
                Write-Host "Executing: $($Step.Name) (Attempt $Attempt)" -ForegroundColor Yellow
                & $Step.Function
                $Success = $true
                Write-Host "Completed: $($Step.Name)" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed: $($Step.Name) - $($_.Exception.Message)"
                $Attempt++
                
                if ($Attempt -gt $Step.RetryCount) {
                    Write-Error "Failed to complete $($Step.Name) after $($Step.RetryCount) attempts"
                    return $false
                }
                
                Start-Sleep -Seconds 5
            }
        } while (-not $Success -and $Attempt -le $Step.RetryCount)
    }
    
    Write-Host "User onboarding workflow completed successfully" -ForegroundColor Green
    return $true
}
```

### Event-Driven Automation
```powershell
function Register-EventDrivenAutomation {
    # Register for Azure AD events
    Register-Event -SourceIdentifier "AzureAD.UserCreated" -Action {
        $User = $Event.SourceEventArgs
        Write-Host "New user created: $($User.UserPrincipalName)" -ForegroundColor Green
        
        # Trigger automated onboarding
        Start-UserOnboardingWorkflow -UserPrincipalName $User.UserPrincipalName
    }
    
    # Register for device compliance events
    Register-Event -SourceIdentifier "Intune.DeviceNonCompliant" -Action {
        $Device = $Event.SourceEventArgs
        Write-Host "Device non-compliant: $($Device.DeviceName)" -ForegroundColor Yellow
        
        # Trigger remediation
        Start-DeviceRemediation -DeviceId $Device.Id
    }
}
```

## Advanced Monitoring and Analytics

### Comprehensive Health Dashboard
```powershell
function Get-ComprehensiveHealthDashboard {
    $Dashboard = @{
        Timestamp = Get-Date
        OverallStatus = "Healthy"
        Services = @{}
        Metrics = @{}
        Alerts = @()
        Recommendations = @()
    }
    
    # Check all M365 services
    $Services = @("AzureAD", "Intune", "Exchange", "SharePoint", "Teams", "Purview")
    
    foreach ($Service in $Services) {
        $ServiceHealth = Get-ServiceHealth -ServiceName $Service
        $Dashboard.Services[$Service] = $ServiceHealth
        
        if ($ServiceHealth.Status -ne "Healthy") {
            $Dashboard.Alerts += "Service $Service is $($ServiceHealth.Status)"
            $Dashboard.OverallStatus = "Degraded"
        }
    }
    
    # Calculate key metrics
    $Dashboard.Metrics = @{
        TotalUsers = (Get-AzureADUser).Count
        ActiveUsers = (Get-AzureADUser -Filter "AccountEnabled eq true").Count
        CompliantDevices = (Get-MgDeviceManagementManagedDevice | Where-Object {$_.ComplianceState -eq "Compliant"}).Count
        TotalDevices = (Get-MgDeviceManagementManagedDevice).Count
        DLPIncidents = (Search-UnifiedAuditLog -Operations "DLPAction" -StartDate (Get-Date).AddDays(-7)).Count
    }
    
    # Generate recommendations
    $ComplianceRate = [math]::Round(($Dashboard.Metrics.CompliantDevices / $Dashboard.Metrics.TotalDevices) * 100, 2)
    if ($ComplianceRate -lt 90) {
        $Dashboard.Recommendations += "Device compliance rate is $ComplianceRate%. Consider reviewing compliance policies."
    }
    
    return $Dashboard
}
```

### Predictive Analytics
```powershell
function Get-PredictiveAnalytics {
    $Analytics = @{
        UserGrowth = @{}
        LicenseUtilization = @{}
        StorageTrends = @{}
        SecurityTrends = @{}
    }
    
    # Analyze user growth trends
    $UserGrowthData = Get-AzureADUser -All $true | Group-Object {$_.CreatedDateTime.ToString("yyyy-MM")}
    $Analytics.UserGrowth = $UserGrowthData | ForEach-Object {
        @{
            Month = $_.Name
            NewUsers = $_.Count
        }
    }
    
    # Analyze license utilization
    $Licenses = Get-AzureADSubscribedSku
    foreach ($License in $Licenses) {
        $UtilizationRate = [math]::Round(($License.ConsumedUnits / $License.PrepaidUnits.Enabled) * 100, 2)
        $Analytics.LicenseUtilization[$License.SkuPartNumber] = @{
            Consumed = $License.ConsumedUnits
            Available = $License.PrepaidUnits.Enabled
            UtilizationRate = $UtilizationRate
        }
    }
    
    # Analyze security trends
    $SecurityEvents = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -Operations @("UserLoggedIn", "UserLogonFailed")
    $Analytics.SecurityTrends = $SecurityEvents | Group-Object Operations | ForEach-Object {
        @{
            EventType = $_.Name
            Count = $_.Count
            Trend = "Stable"  # Simplified - would need historical comparison
        }
    }
    
    return $Analytics
}
```

## Disaster Recovery and Business Continuity

### Backup and Recovery Procedures
```powershell
function Start-ComprehensiveBackup {
    $BackupReport = @{
        Timestamp = Get-Date
        Status = "InProgress"
        Components = @{}
    }
    
    # Backup Azure AD configuration
    try {
        $AzureADConfig = @{
            Users = Get-AzureADUser -All $true
            Groups = Get-AzureADGroup -All $true
            Policies = Get-AzureADPolicy
        }
        
        $AzureADConfig | Export-Clixml -Path "C:\Backups\AzureAD_Config_$(Get-Date -Format 'yyyyMMdd').xml"
        $BackupReport.Components.AzureAD = "Success"
    }
    catch {
        $BackupReport.Components.AzureAD = "Failed: $($_.Exception.Message)"
    }
    
    # Backup Intune configuration
    try {
        $IntuneConfig = @{
            Devices = Get-MgDeviceManagementManagedDevice -All
            Policies = Get-MgDeviceManagementDeviceCompliancePolicy -All
            Applications = Get-MgDeviceAppManagementMobileApp -All
        }
        
        $IntuneConfig | Export-Clixml -Path "C:\Backups\Intune_Config_$(Get-Date -Format 'yyyyMMdd').xml"
        $BackupReport.Components.Intune = "Success"
    }
    catch {
        $BackupReport.Components.Intune = "Failed: $($_.Exception.Message)"
    }
    
    # Backup Purview configuration
    try {
        Connect-IPPSSession
        $PurviewConfig = @{
            Labels = Get-Label
            DLPolicies = Get-DlpCompliancePolicy
            RetentionPolicies = Get-RetentionCompliancePolicy
        }
        
        $PurviewConfig | Export-Clixml -Path "C:\Backups\Purview_Config_$(Get-Date -Format 'yyyyMMdd').xml"
        $BackupReport.Components.Purview = "Success"
        Disconnect-IPPSSession
    }
    catch {
        $BackupReport.Components.Purview = "Failed: $($_.Exception.Message)"
    }
    
    $BackupReport.Status = "Completed"
    return $BackupReport
}
```

### Disaster Recovery Testing
```powershell
function Test-DisasterRecovery {
    $TestResults = @{
        Timestamp = Get-Date
        Tests = @{}
        OverallStatus = "Passed"
    }
    
    # Test user authentication
    try {
        $TestUser = Get-AzureADUser -Top 1
        $AuthTest = Test-AzureADUserAuthentication -UserPrincipalName $TestUser.UserPrincipalName
        $TestResults.Tests.Authentication = "Passed"
    }
    catch {
        $TestResults.Tests.Authentication = "Failed: $($_.Exception.Message)"
        $TestResults.OverallStatus = "Failed"
    }
    
    # Test device compliance
    try {
        $CompliantDevices = Get-MgDeviceManagementManagedDevice | Where-Object {$_.ComplianceState -eq "Compliant"}
        if ($CompliantDevices.Count -gt 0) {
            $TestResults.Tests.DeviceCompliance = "Passed"
        } else {
            $TestResults.Tests.DeviceCompliance = "Warning: No compliant devices found"
        }
    }
    catch {
        $TestResults.Tests.DeviceCompliance = "Failed: $($_.Exception.Message)"
        $TestResults.OverallStatus = "Failed"
    }
    
    # Test data access
    try {
        $TestAccess = Get-MgUser -Top 1
        $TestResults.Tests.DataAccess = "Passed"
    }
    catch {
        $TestResults.Tests.DataAccess = "Failed: $($_.Exception.Message)"
        $TestResults.OverallStatus = "Failed"
    }
    
    return $TestResults
}
```

## Performance Optimization

### Advanced Caching Strategies
```powershell
function Initialize-PerformanceCache {
    $Cache = @{
        Users = @{}
        Groups = @{}
        Devices = @{}
        LastUpdated = @{}
        TTL = 300  # 5 minutes
    }
    
    # Pre-populate cache with frequently accessed data
    $Cache.Users = Get-AzureADUser -All $true | ForEach-Object {
        @{$_.UserPrincipalName = $_}
    }
    
    $Cache.Groups = Get-AzureADGroup -All $true | ForEach-Object {
        @{$_.DisplayName = $_}
    }
    
    $Cache.LastUpdated.Users = Get-Date
    $Cache.LastUpdated.Groups = Get-Date
    
    return $Cache
}

function Get-CachedData {
    param(
        [hashtable]$Cache,
        [string]$DataType,
        [string]$Key
    )
    
    $Now = Get-Date
    $LastUpdate = $Cache.LastUpdated[$DataType]
    
    # Check if cache is expired
    if ($LastUpdate -and ($Now - $LastUpdate).TotalSeconds -gt $Cache.TTL) {
        Write-Host "Cache expired for $DataType, refreshing..." -ForegroundColor Yellow
        
        # Refresh cache
        switch ($DataType) {
            "Users" {
                $Cache.Users = Get-AzureADUser -All $true | ForEach-Object {
                    @{$_.UserPrincipalName = $_}
                }
            }
            "Groups" {
                $Cache.Groups = Get-AzureADGroup -All $true | ForEach-Object {
                    @{$_.DisplayName = $_}
                }
            }
        }
        
        $Cache.LastUpdated[$DataType] = $Now
    }
    
    return $Cache[$DataType][$Key]
}
```

### Parallel Processing
```powershell
function Invoke-ParallelProcessing {
    param(
        [array]$Items,
        [scriptblock]$ScriptBlock,
        [int]$MaxConcurrency = 10
    )
    
    $Jobs = @()
    $Results = @()
    
    foreach ($Item in $Items) {
        # Wait if we've reached max concurrency
        while ((Get-Job -State Running).Count -ge $MaxConcurrency) {
            Start-Sleep -Milliseconds 100
        }
        
        # Start new job
        $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Item
        $Jobs += $Job
    }
    
    # Wait for all jobs to complete
    $Jobs | Wait-Job | Out-Null
    
    # Collect results
    foreach ($Job in $Jobs) {
        $Results += Receive-Job -Job $Job
        Remove-Job -Job $Job
    }
    
    return $Results
}
```

## Best Practices for Advanced Scenarios

### Security
1. **Zero Trust**: Implement zero trust architecture
2. **Advanced Threat Protection**: Use all available security features
3. **Regular Security Assessments**: Conduct regular security reviews
4. **Incident Response**: Have comprehensive incident response procedures

### Performance
1. **Caching**: Implement intelligent caching strategies
2. **Parallel Processing**: Use parallel processing for bulk operations
3. **Monitoring**: Monitor performance metrics continuously
4. **Optimization**: Regularly optimize queries and operations

### Automation
1. **Workflow Design**: Design robust, fault-tolerant workflows
2. **Error Handling**: Implement comprehensive error handling
3. **Testing**: Thoroughly test all automation scripts
4. **Documentation**: Document all automation procedures

### Disaster Recovery
1. **Regular Backups**: Maintain regular backups of all configurations
2. **Testing**: Regularly test disaster recovery procedures
3. **Documentation**: Document all recovery procedures
4. **Training**: Train staff on disaster recovery procedures

---

*This guide covers advanced M365 administration topics. For implementation, ensure you have appropriate permissions and test all procedures in a development environment first.*
