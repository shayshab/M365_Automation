# PowerShell Automation

## Essential PowerShell Modules

### Core M365 Modules
```powershell
# Microsoft Graph (Modern PowerShell)
Install-Module -Name Microsoft.Graph -Force

# Azure AD (Legacy but still useful)
Install-Module -Name AzureAD -Force

# Exchange Online
Install-Module -Name ExchangeOnlineManagement -Force

# Teams
Install-Module -Name MicrosoftTeams -Force

# SharePoint Online
Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Force

# Security & Compliance
Install-Module -Name SecurityComplianceCenter -Force

# Azure (for cloud services)
Install-Module -Name Az -Force

# Active Directory (for on-premises)
Install-Module -Name ActiveDirectory -Force
```

## Advanced Automation Scripts

### User Lifecycle Management
```powershell
function New-EmployeeOnboarding {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$true)]
        [string]$Department,
        [Parameter(Mandatory=$true)]
        [string]$JobTitle
    )
    
    try {
        # Connect to services
        Connect-AzureAD
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All"
        
        # Generate temporary password
        $TempPassword = [System.Web.Security.Membership]::GeneratePassword(12, 4)
        
        # Create user
        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        $PasswordProfile.Password = $TempPassword
        $PasswordProfile.ForceChangePasswordNextLogin = $true
        
        $NewUser = New-AzureADUser -DisplayName $DisplayName `
                                  -UserPrincipalName $UserPrincipalName `
                                  -PasswordProfile $PasswordProfile `
                                  -AccountEnabled $true `
                                  -JobTitle $JobTitle `
                                  -Department $Department
        
        # Add to department group
        $DepartmentGroup = Get-AzureADGroup -Filter "DisplayName eq '$Department'"
        if ($DepartmentGroup) {
            Add-AzureADGroupMember -ObjectId $DepartmentGroup.ObjectId -RefObjectId $NewUser.ObjectId
        }
        
        # Assign licenses
        $AccountSku = Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq "ENTERPRISEPACK"}
        Set-AzureADUserLicense -ObjectId $NewUser.ObjectId -AssignedLicenses @{SkuId = $AccountSku.SkuId}
        
        Write-Host "User $DisplayName created successfully" -ForegroundColor Green
        return @{
            User = $NewUser
            TemporaryPassword = $TempPassword
            Success = $true
        }
    }
    catch {
        Write-Error "Failed to create user: $($_.Exception.Message)"
        return @{
            User = $null
            TemporaryPassword = $null
            Success = $false
            Error = $_.Exception.Message
        }
    }
}
```

### Group Management Automation
```powershell
function Sync-DepartmentGroups {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CSVPath
    )
    
    $Users = Import-Csv -Path $CSVPath
    
    foreach ($User in $Users) {
        $AzureUser = Get-AzureADUser -Filter "UserPrincipalName eq '$($User.UserPrincipalName)'"
        
        if ($AzureUser) {
            # Get current groups
            $CurrentGroups = Get-AzureADUserMembership -ObjectId $AzureUser.ObjectId | Where-Object {$_.ObjectType -eq "Group"}
            
            # Remove from old department groups
            $DepartmentGroups = Get-AzureADGroup -Filter "startswith(DisplayName,'Dept-')"
            foreach ($Group in $DepartmentGroups) {
                if ($CurrentGroups.ObjectId -contains $Group.ObjectId) {
                    Remove-AzureADGroupMember -ObjectId $Group.ObjectId -MemberId $AzureUser.ObjectId
                }
            }
            
            # Add to new department group
            $TargetGroup = Get-AzureADGroup -Filter "DisplayName eq 'Dept-$($User.Department)'"
            if ($TargetGroup) {
                Add-AzureADGroupMember -ObjectId $TargetGroup.ObjectId -RefObjectId $AzureUser.ObjectId
            }
        }
    }
}
```

### Policy Enforcement Script
```powershell
function Enforce-SecurityPolicies {
    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All", "Policy.ReadWrite.All"
    
    # Get non-compliant devices
    $NonCompliantDevices = Get-MgDeviceManagementManagedDevice | Where-Object {$_.ComplianceState -ne "Compliant"}
    
    foreach ($Device in $NonCompliantDevices) {
        Write-Host "Processing non-compliant device: $($Device.DeviceName)" -ForegroundColor Yellow
        
        # Send compliance notification
        Send-MgDeviceManagementManagedDeviceNotification -ManagedDeviceId $Device.Id -NotificationType "complianceCheckIn"
        
        # Apply remediation actions
        if ($Device.ComplianceState -eq "NonCompliant") {
            # Restrict access or apply additional policies
            Write-Host "Applying remediation to device: $($Device.DeviceName)" -ForegroundColor Red
        }
    }
    
    # Update conditional access policies
    $CAPolicies = Get-MgIdentityConditionalAccessPolicy
    foreach ($Policy in $CAPolicies) {
        if ($Policy.State -eq "Disabled") {
            Write-Host "Enabling conditional access policy: $($Policy.DisplayName)" -ForegroundColor Green
            Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -State "Enabled"
        }
    }
}
```

## Multi-Tenant Management
```powershell
function Manage-MultipleTenants {
    $Tenants = @("tenant1.onmicrosoft.com", "tenant2.onmicrosoft.com")

    foreach ($Tenant in $Tenants) {
        Connect-AzureAD -TenantId $Tenant
        
        # Apply consistent policies across tenants
        $Policy = @{
            DisplayName = "Standard Security Policy"
            Description = "Applied across all tenants"
            # Policy configuration
        }
        
        # Deploy policy
        Write-Host "Deploying policy to $Tenant" -ForegroundColor Green
    }
}
```

## Advanced Monitoring and Reporting
```powershell
function Get-M365HealthStatus {
    $HealthReport = @{}
    
    # Check Entra ID health
    try {
        $Users = Get-AzureADUser -All $true
        $HealthReport.EntraID = @{
            Status = "Healthy"
            UserCount = $Users.Count
            LastCheck = Get-Date
        }
    }
    catch {
        $HealthReport.EntraID = @{
            Status = "Error"
            Error = $_.Exception.Message
            LastCheck = Get-Date
        }
    }
    
    # Check Intune device compliance
    try {
        Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All"
        $Devices = Get-MgDeviceManagementManagedDevice -All
        $CompliantDevices = ($Devices | Where-Object {$_.ComplianceState -eq "Compliant"}).Count
        $TotalDevices = $Devices.Count
        
        $HealthReport.Intune = @{
            Status = if ($CompliantDevices -eq $TotalDevices) { "Healthy" } else { "Warning" }
            CompliantDevices = $CompliantDevices
            TotalDevices = $TotalDevices
            ComplianceRate = [math]::Round(($CompliantDevices / $TotalDevices) * 100, 2)
            LastCheck = Get-Date
        }
    }
    catch {
        $HealthReport.Intune = @{
            Status = "Error"
            Error = $_.Exception.Message
            LastCheck = Get-Date
        }
    }
    
    return $HealthReport
}
```

## Security Best Practices
```powershell
function Apply-SecurityBaseline {
    # Enable MFA for all users
    $Users = Get-AzureADUser -All $true | Where-Object {$_.AccountEnabled -eq $true}
    
    foreach ($User in $Users) {
        # Check if MFA is enabled
        $MFAStatus = Get-AzureADUser -ObjectId $User.ObjectId | Select-Object -ExpandProperty StrongAuthenticationRequirements
        
        if (-not $MFAStatus) {
            Write-Host "Enabling MFA for $($User.UserPrincipalName)" -ForegroundColor Yellow
            # Enable MFA (requires additional configuration)
        }
    }
    
    # Configure conditional access policies
    $CAPolicy = @{
        "@odata.type" = "#microsoft.graph.conditionalAccessPolicy"
        displayName = "Require MFA for all users"
        state = "Enabled"
        conditions = @{
            applications = @{
                includeApplications = @("All")
            }
            users = @{
                includeUsers = @("All")
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = @("mfa")
        }
    }
    
    New-MgIdentityConditionalAccessPolicy -BodyParameter $CAPolicy
}
```

## Error Handling and Logging
```powershell
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Info" { Write-Host $LogMessage -ForegroundColor White }
        "Warning" { Write-Host $LogMessage -ForegroundColor Yellow }
        "Error" { Write-Host $LogMessage -ForegroundColor Red }
        "Success" { Write-Host $LogMessage -ForegroundColor Green }
    }
    
    # Also write to log file
    $LogMessage | Out-File -FilePath "M365_Automation.log" -Append
}

function Invoke-SafeCommand {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$Command,
        [Parameter(Mandatory=$false)]
        [string]$ErrorMessage = "Command failed"
    )
    
    try {
        $Result = & $Command
        Write-Log "Command executed successfully" "Success"
        return $Result
    }
    catch {
        Write-Log "$ErrorMessage : $($_.Exception.Message)" "Error"
        return $null
    }
}
```

## Performance Optimization
```powershell
function Optimize-BulkOperations {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Items,
        [Parameter(Mandatory=$true)]
        [scriptblock]$Operation,
        [Parameter(Mandatory=$false)]
        [int]$BatchSize = 10,
        [Parameter(Mandatory=$false)]
        [int]$DelaySeconds = 1
    )
    
    $Batches = @()
    for ($i = 0; $i -lt $Items.Count; $i += $BatchSize) {
        $Batches += , $Items[$i..($i + $BatchSize - 1)]
    }
    
    foreach ($Batch in $Batches) {
        $Jobs = @()
        
        foreach ($Item in $Batch) {
            $Job = Start-Job -ScriptBlock {
                param($Item, $Operation)
                & $Operation $Item
            } -ArgumentList $Item, $Operation
            
            $Jobs += $Job
        }
        
        # Wait for batch to complete
        $Jobs | Wait-Job | Receive-Job
        $Jobs | Remove-Job
        
        # Add delay between batches to avoid throttling
        Start-Sleep -Seconds $DelaySeconds
    }
}
```

## Scheduled Tasks and Automation
```powershell
function Register-M365ScheduledTasks {
    # Daily user maintenance
    $DailyAction = {
        . "C:\Scripts\M365_User_Management.ps1"
        Connect-M365Services
        Start-UserMaintenance -CleanupDisabledAccounts -UpdateLicenses
        Disconnect-M365Services
    }
    
    Register-ScheduledTask -TaskName "M365 Daily User Maintenance" `
                          -Action (New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-Command `"& {$DailyAction}`"") `
                          -Trigger (New-ScheduledTaskTrigger -Daily -At "02:00") `
                          -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries)
    
    # Weekly compliance report
    $WeeklyAction = {
        . "C:\Scripts\M365_Compliance_Reporting.ps1"
        Connect-M365Services
        Generate-ComplianceReport -OutputPath "C:\Reports\Weekly_Compliance_$(Get-Date -Format 'yyyyMMdd').json"
        Disconnect-M365Services
    }
    
    Register-ScheduledTask -TaskName "M365 Weekly Compliance Report" `
                          -Action (New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-Command `"& {$WeeklyAction}`"") `
                          -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "08:00") `
                          -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries)
}
```

## Best Practices

### PowerShell Best Practices
1. **Error Handling**: Always use try-catch blocks
2. **Logging**: Implement comprehensive logging
3. **Modularity**: Create reusable functions
4. **Documentation**: Comment your code thoroughly
5. **Testing**: Test scripts in a development environment first

### Security Considerations
1. **Least Privilege**: Use minimum required permissions
2. **Secure Credentials**: Use Azure Key Vault for secrets
3. **Audit Logging**: Enable audit logs for all operations
4. **Regular Reviews**: Regularly review and update policies
5. **Incident Response**: Have procedures for security incidents

### Performance Optimization
1. **Batch Operations**: Process multiple items together
2. **Filtering**: Use filters to reduce data transfer
3. **Pagination**: Handle large result sets properly
4. **Caching**: Cache frequently accessed data
5. **Parallel Processing**: Use parallel execution where possible

### Automation Guidelines
1. **Idempotency**: Scripts should be safe to run multiple times
2. **Validation**: Validate inputs and outputs
3. **Rollback**: Implement rollback procedures
4. **Monitoring**: Monitor automated processes
5. **Documentation**: Document all automated processes

---

*This guide covers advanced PowerShell automation for M365. For specific service implementations, refer to the individual service documentation and scripts.*
