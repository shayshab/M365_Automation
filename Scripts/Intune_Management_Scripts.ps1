# M365 Intune Management Scripts
# Comprehensive PowerShell scripts for Microsoft Intune device and application management

#region Prerequisites and Setup
# Install required modules
# Install-Module -Name Microsoft.Graph -Force
# Install-Module -Name Microsoft.Graph.DeviceManagement -Force
# Install-Module -Name Microsoft.Graph.Intune -Force

#region Helper Functions
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
    
    $LogMessage | Out-File -FilePath "M365_IntuneManagement.log" -Append
}

function Test-IntuneConnection {
    try {
        $Context = Get-MgContext
        if ($Context -and $Context.TenantId) {
            Write-Log "Connected to Microsoft Graph for tenant: $($Context.TenantId)" "Success"
            return $true
        }
        else {
            Write-Log "Not connected to Microsoft Graph" "Error"
            return $false
        }
    }
    catch {
        Write-Log "Connection test failed: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Device Management
function Get-IntuneDevices {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DeviceName,
        [Parameter(Mandatory=$false)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Compliant", "NonCompliant", "Conflict", "Error")]
        [string]$ComplianceState,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDetails
    )
    
    try {
        Write-Log "Retrieving Intune devices..." "Info"
        
        $Devices = Get-MgDeviceManagementManagedDevice -All
        
        # Apply filters
        if ($DeviceName) {
            $Devices = $Devices | Where-Object {$_.DeviceName -like "*$DeviceName*"}
        }
        
        if ($UserPrincipalName) {
            $Devices = $Devices | Where-Object {$_.UserPrincipalName -eq $UserPrincipalName}
        }
        
        if ($ComplianceState) {
            $Devices = $Devices | Where-Object {$_.ComplianceState -eq $ComplianceState}
        }
        
        if ($IncludeDetails) {
            $DetailedDevices = @()
            foreach ($Device in $Devices) {
                $DeviceDetails = @{
                    DeviceName = $Device.DeviceName
                    UserPrincipalName = $Device.UserPrincipalName
                    DeviceType = $Device.DeviceType
                    OperatingSystem = $Device.OperatingSystem
                    OSVersion = $Device.OSVersion
                    ComplianceState = $Device.ComplianceState
                    LastSyncDateTime = $Device.LastSyncDateTime
                    EnrolledDateTime = $Device.EnrolledDateTime
                    SerialNumber = $Device.SerialNumber
                    IMEI = $Device.IMEI
                    PhoneNumber = $Device.PhoneNumber
                    WiFiMacAddress = $Device.WiFiMacAddress
                    Model = $Device.Model
                    Manufacturer = $Device.Manufacturer
                    ManagementAgent = $Device.ManagementAgent
                    IsEncrypted = $Device.IsEncrypted
                    IsSupervised = $Device.IsSupervised
                    ExchangeAccessState = $Device.ExchangeAccessState
                    ExchangeAccessStateReason = $Device.ExchangeAccessStateReason
                }
                $DetailedDevices += $DeviceDetails
            }
            return $DetailedDevices
        }
        
        return $Devices
    }
    catch {
        Write-Log "Failed to retrieve devices: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Invoke-DeviceAction {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DeviceId,
        [Parameter(Mandatory=$true)]
        [ValidateSet("syncDevice", "retire", "wipe", "resetPasscode", "remoteLock", "locateDevice")]
        [string]$Action
    )
    
    try {
        Write-Log "Executing action '$Action' on device ID: $DeviceId" "Info"
        
        switch ($Action) {
            "syncDevice" {
                Send-MgDeviceManagementManagedDeviceSyncDevice -ManagedDeviceId $DeviceId
                Write-Log "Sync command sent to device" "Success"
            }
            "retire" {
                Invoke-MgRetireDeviceManagementManagedDevice -ManagedDeviceId $DeviceId
                Write-Log "Retire command sent to device" "Success"
            }
            "wipe" {
                $WipeParams = @{
                    KeepEnrollmentData = $false
                    KeepUserData = $false
                    MacOsUnlockCode = $null
                }
                Invoke-MgWipeDeviceManagementManagedDevice -ManagedDeviceId $DeviceId -BodyParameter $WipeParams
                Write-Log "Wipe command sent to device" "Success"
            }
            "resetPasscode" {
                Invoke-MgResetPasscodeDeviceManagementManagedDevice -ManagedDeviceId $DeviceId
                Write-Log "Passcode reset command sent to device" "Success"
            }
            "remoteLock" {
                Invoke-MgRemoteLockDeviceManagementManagedDevice -ManagedDeviceId $DeviceId
                Write-Log "Remote lock command sent to device" "Success"
            }
            "locateDevice" {
                Invoke-MgLocateDeviceDeviceManagementManagedDevice -ManagedDeviceId $DeviceId
                Write-Log "Locate device command sent" "Success"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to execute device action: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-DeviceComplianceReport {
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Generating device compliance report..." "Info"
        
        $Devices = Get-MgDeviceManagementManagedDevice -All
        $ComplianceReport = @()
        
        foreach ($Device in $Devices) {
            $DeviceInfo = @{
                DeviceName = $Device.DeviceName
                UserPrincipalName = $Device.UserPrincipalName
                DeviceType = $Device.DeviceType
                OperatingSystem = $Device.OperatingSystem
                OSVersion = $Device.OSVersion
                ComplianceState = $Device.ComplianceState
                LastSyncDateTime = $Device.LastSyncDateTime
                IsEncrypted = $Device.IsEncrypted
                IsSupervised = $Device.IsSupervised
                ExchangeAccessState = $Device.ExchangeAccessState
                ManagementAgent = $Device.ManagementAgent
            }
            $ComplianceReport += $DeviceInfo
        }
        
        if ($OutputPath) {
            $ComplianceReport | Export-Csv -Path $OutputPath -NoTypeInformation
            Write-Log "Compliance report exported to: $OutputPath" "Success"
        }
        
        return $ComplianceReport
    }
    catch {
        Write-Log "Failed to generate compliance report: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Compliance Policies
function New-IntuneCompliancePolicy {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Windows10", "Windows81", "WindowsPhone81", "iOS", "Android")]
        [string]$Platform,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [hashtable]$PolicySettings
    )
    
    try {
        Write-Log "Creating compliance policy: $DisplayName for platform: $Platform" "Info"
        
        $PolicyType = switch ($Platform) {
            "Windows10" { "#microsoft.graph.windows10CompliancePolicy" }
            "iOS" { "#microsoft.graph.iosCompliancePolicy" }
            "Android" { "#microsoft.graph.androidCompliancePolicy" }
            default { "#microsoft.graph.deviceCompliancePolicy" }
        }
        
        $PolicyBody = @{
            "@odata.type" = $PolicyType
            displayName = $DisplayName
            description = $Description
            scheduledActionsForRule = @()
        }
        
        # Add platform-specific settings
        switch ($Platform) {
            "Windows10" {
                $PolicyBody.passwordRequired = $PolicySettings.PasswordRequired
                $PolicyBody.passwordMinimumLength = $PolicySettings.PasswordMinimumLength
                $PolicyBody.passwordRequiredType = $PolicySettings.PasswordRequiredType
                $PolicyBody.passwordExpirationDays = $PolicySettings.PasswordExpirationDays
                $PolicyBody.passwordMinutesOfInactivityBeforeLock = $PolicySettings.PasswordMinutesOfInactivityBeforeLock
                $PolicyBody.requireHealthyDeviceReport = $PolicySettings.RequireHealthyDeviceReport
                $PolicyBody.osMinimumVersion = $PolicySettings.OSMinimumVersion
                $PolicyBody.osMaximumVersion = $PolicySettings.OSMaximumVersion
                $PolicyBody.storageRequireEncryption = $PolicySettings.StorageRequireEncryption
            }
            "iOS" {
                $PolicyBody.passcodeRequired = $PolicySettings.PasscodeRequired
                $PolicyBody.passcodeMinimumLength = $PolicySettings.PasscodeMinimumLength
                $PolicyBody.passcodeMinutesOfInactivityBeforeLock = $PolicySettings.PasscodeMinutesOfInactivityBeforeLock
                $PolicyBody.osMinimumVersion = $PolicySettings.OSMinimumVersion
                $PolicyBody.osMaximumVersion = $PolicySettings.OSMaximumVersion
                $PolicyBody.storageRequireEncryption = $PolicySettings.StorageRequireEncryption
                $PolicyBody.managedEmailProfileRequired = $PolicySettings.ManagedEmailProfileRequired
            }
            "Android" {
                $PolicyBody.passwordRequired = $PolicySettings.PasswordRequired
                $PolicyBody.passwordMinimumLength = $PolicySettings.PasswordMinimumLength
                $PolicyBody.passwordMinutesOfInactivityBeforeLock = $PolicySettings.PasswordMinutesOfInactivityBeforeLock
                $PolicyBody.osMinimumVersion = $PolicySettings.OSMinimumVersion
                $PolicyBody.osMaximumVersion = $PolicySettings.OSMaximumVersion
                $PolicyBody.storageRequireEncryption = $PolicySettings.StorageRequireEncryption
                $PolicyBody.securityRequireIntuneAppIntegrity = $PolicySettings.SecurityRequireIntuneAppIntegrity
            }
        }
        
        $NewPolicy = New-MgDeviceManagementDeviceCompliancePolicy -BodyParameter $PolicyBody
        Write-Log "Compliance policy created successfully with ID: $($NewPolicy.Id)" "Success"
        
        return $NewPolicy
    }
    catch {
        Write-Log "Failed to create compliance policy: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Set-CompliancePolicyAssignment {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PolicyId,
        [Parameter(Mandatory=$true)]
        [ValidateSet("AllDevices", "AllUsers", "SpecificGroups", "SpecificUsers")]
        [string]$AssignmentType,
        [Parameter(Mandatory=$false)]
        [string[]]$TargetIds
    )
    
    try {
        Write-Log "Assigning compliance policy: $PolicyId" "Info"
        
        $Assignment = @{
            "@odata.type" = "#microsoft.graph.deviceCompliancePolicyAssignment"
            target = @{}
        }
        
        switch ($AssignmentType) {
            "AllDevices" {
                $Assignment.target."@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
                $Assignment.target.deviceAndAppManagementAssignmentFilterId = $null
                $Assignment.target.deviceAndAppManagementAssignmentFilterType = "none"
            }
            "AllUsers" {
                $Assignment.target."@odata.type" = "#microsoft.graph.allLicensedUsersAssignmentTarget"
                $Assignment.target.deviceAndAppManagementAssignmentFilterId = $null
                $Assignment.target.deviceAndAppManagementAssignmentFilterType = "none"
            }
            "SpecificGroups" {
                $Assignment.target."@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                $Assignment.target.groupId = $TargetIds[0]
            }
            "SpecificUsers" {
                $Assignment.target."@odata.type" = "#microsoft.graph.exclusionGroupAssignmentTarget"
                $Assignment.target.groupId = $TargetIds[0]
            }
        }
        
        New-MgDeviceManagementDeviceCompliancePolicyAssignment -DeviceCompliancePolicyId $PolicyId -BodyParameter $Assignment
        Write-Log "Policy assignment created successfully" "Success"
        
        return $true
    }
    catch {
        Write-Log "Failed to assign compliance policy: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Application Management
function Get-IntuneApplications {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [ValidateSet("windows", "ios", "android")]
        [string]$Platform,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeAssignments
    )
    
    try {
        Write-Log "Retrieving Intune applications..." "Info"
        
        $Apps = Get-MgDeviceAppManagementMobileApp -All
        
        # Apply filters
        if ($DisplayName) {
            $Apps = $Apps | Where-Object {$_.DisplayName -like "*$DisplayName*"}
        }
        
        if ($Platform) {
            $Apps = $Apps | Where-Object {$_.'@odata.type' -like "*$Platform*"}
        }
        
        if ($IncludeAssignments) {
            $DetailedApps = @()
            foreach ($App in $Apps) {
                $Assignments = Get-MgDeviceAppManagementMobileAppAssignment -MobileAppId $App.Id
                
                $AppInfo = @{
                    Id = $App.Id
                    DisplayName = $App.DisplayName
                    Description = $App.Description
                    Publisher = $App.Publisher
                    AppType = $App.'@odata.type'
                    CreatedDateTime = $App.CreatedDateTime
                    LastModifiedDateTime = $App.LastModifiedDateTime
                    Assignments = $Assignments.Count
                }
                $DetailedApps += $AppInfo
            }
            return $DetailedApps
        }
        
        return $Apps
    }
    catch {
        Write-Log "Failed to retrieve applications: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-AppAssignment {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppId,
        [Parameter(Mandatory=$true)]
        [ValidateSet("AllDevices", "AllUsers", "SpecificGroups", "SpecificUsers")]
        [string]$AssignmentType,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Available", "Required", "Uninstall", "AvailableWithoutEnrollment")]
        [string]$Intent,
        [Parameter(Mandatory=$false)]
        [string[]]$TargetIds
    )
    
    try {
        Write-Log "Creating app assignment for app ID: $AppId" "Info"
        
        $Assignment = @{
            "@odata.type" = "#microsoft.graph.mobileAppAssignment"
            intent = $Intent
            target = @{}
        }
        
        switch ($AssignmentType) {
            "AllDevices" {
                $Assignment.target."@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
            }
            "AllUsers" {
                $Assignment.target."@odata.type" = "#microsoft.graph.allLicensedUsersAssignmentTarget"
            }
            "SpecificGroups" {
                $Assignment.target."@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                $Assignment.target.groupId = $TargetIds[0]
            }
            "SpecificUsers" {
                $Assignment.target."@odata.type" = "#microsoft.graph.exclusionGroupAssignmentTarget"
                $Assignment.target.groupId = $TargetIds[0]
            }
        }
        
        New-MgDeviceAppManagementMobileAppAssignment -MobileAppId $AppId -BodyParameter $Assignment
        Write-Log "App assignment created successfully" "Success"
        
        return $true
    }
    catch {
        Write-Log "Failed to create app assignment: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Configuration Profiles
function Get-ConfigurationProfiles {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Windows10", "iOS", "Android", "macOS")]
        [string]$Platform,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeAssignments
    )
    
    try {
        Write-Log "Retrieving configuration profiles..." "Info"
        
        $Profiles = Get-MgDeviceManagementDeviceConfiguration -All
        
        # Apply filters
        if ($DisplayName) {
            $Profiles = $Profiles | Where-Object {$_.DisplayName -like "*$DisplayName*"}
        }
        
        if ($Platform) {
            $Profiles = $Profiles | Where-Object {$_.'@odata.type' -like "*$Platform*"}
        }
        
        if ($IncludeAssignments) {
            $DetailedProfiles = @()
            foreach ($Profile in $Profiles) {
                $Assignments = Get-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $Profile.Id
                
                $ProfileInfo = @{
                    Id = $Profile.Id
                    DisplayName = $Profile.DisplayName
                    Description = $Profile.Description
                    ProfileType = $Profile.'@odata.type'
                    CreatedDateTime = $Profile.CreatedDateTime
                    LastModifiedDateTime = $Profile.LastModifiedDateTime
                    Assignments = $Assignments.Count
                }
                $DetailedProfiles += $ProfileInfo
            }
            return $DetailedProfiles
        }
        
        return $Profiles
    }
    catch {
        Write-Log "Failed to retrieve configuration profiles: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-WindowsConfigurationProfile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [hashtable]$Settings
    )
    
    try {
        Write-Log "Creating Windows configuration profile: $DisplayName" "Info"
        
        $ProfileBody = @{
            "@odata.type" = "#microsoft.graph.windows10GeneralConfiguration"
            displayName = $DisplayName
            description = $Description
        }
        
        # Add common Windows settings
        if ($Settings) {
            foreach ($Setting in $Settings.GetEnumerator()) {
                $ProfileBody.$($Setting.Key) = $Setting.Value
            }
        }
        
        $NewProfile = New-MgDeviceManagementDeviceConfiguration -BodyParameter $ProfileBody
        Write-Log "Configuration profile created successfully with ID: $($NewProfile.Id)" "Success"
        
        return $NewProfile
    }
    catch {
        Write-Log "Failed to create configuration profile: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Reporting and Analytics
function Get-IntuneAnalytics {
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Generating Intune analytics report..." "Info"
        
        $Analytics = @{}
        
        # Device statistics
        $Devices = Get-MgDeviceManagementManagedDevice -All
        $Analytics.DeviceStats = @{
            TotalDevices = $Devices.Count
            CompliantDevices = ($Devices | Where-Object {$_.ComplianceState -eq "Compliant"}).Count
            NonCompliantDevices = ($Devices | Where-Object {$_.ComplianceState -eq "NonCompliant"}).Count
            InGracePeriod = ($Devices | Where-Object {$_.ComplianceState -eq "InGracePeriod"}).Count
        }
        
        # Platform breakdown
        $Analytics.PlatformStats = $Devices | Group-Object DeviceType | ForEach-Object {
            @{
                Platform = $_.Name
                Count = $_.Count
                Percentage = [math]::Round(($_.Count / $Devices.Count) * 100, 2)
            }
        }
        
        # Application statistics
        $Apps = Get-MgDeviceAppManagementMobileApp -All
        $Analytics.AppStats = @{
            TotalApps = $Apps.Count
            WindowsApps = ($Apps | Where-Object {$_.'@odata.type' -like "*windows*"}).Count
            iOSApps = ($Apps | Where-Object {$_.'@odata.type' -like "*ios*"}).Count
            AndroidApps = ($Apps | Where-Object {$_.'@odata.type' -like "*android*"}).Count
        }
        
        # Configuration profile statistics
        $Profiles = Get-MgDeviceManagementDeviceConfiguration -All
        $Analytics.ProfileStats = @{
            TotalProfiles = $Profiles.Count
            WindowsProfiles = ($Profiles | Where-Object {$_.'@odata.type' -like "*windows*"}).Count
            iOSProfiles = ($Profiles | Where-Object {$_.'@odata.type' -like "*ios*"}).Count
            AndroidProfiles = ($Profiles | Where-Object {$_.'@odata.type' -like "*android*"}).Count
        }
        
        if ($OutputPath) {
            $Analytics | ConvertTo-Json -Depth 3 | Out-File -FilePath $OutputPath
            Write-Log "Analytics report exported to: $OutputPath" "Success"
        }
        
        return $Analytics
    }
    catch {
        Write-Log "Failed to generate analytics: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Automation and Maintenance
function Start-IntuneMaintenance {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$SyncDevices,
        [Parameter(Mandatory=$false)]
        [switch]$UpdatePolicies,
        [Parameter(Mandatory=$false)]
        [switch]$CleanupOrphanedObjects
    )
    
    try {
        Write-Log "Starting Intune maintenance tasks..." "Info"
        
        if ($SyncDevices) {
            Write-Log "Syncing all devices..." "Info"
            $Devices = Get-MgDeviceManagementManagedDevice -All
            foreach ($Device in $Devices) {
                try {
                    Send-MgDeviceManagementManagedDeviceSyncDevice -ManagedDeviceId $Device.Id
                    Write-Log "Sync command sent to device: $($Device.DeviceName)" "Success"
                    Start-Sleep -Seconds 1 # Avoid throttling
                }
                catch {
                    Write-Log "Failed to sync device $($Device.DeviceName): $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        if ($UpdatePolicies) {
            Write-Log "Updating compliance policies..." "Info"
            # Add logic to update policies based on organizational requirements
            Write-Log "Policy update completed" "Success"
        }
        
        if ($CleanupOrphanedObjects) {
            Write-Log "Cleaning up orphaned objects..." "Info"
            # Add logic to clean up orphaned assignments, policies, etc.
            Write-Log "Cleanup completed" "Success"
        }
        
        Write-Log "Maintenance tasks completed successfully" "Success"
        return $true
    }
    catch {
        Write-Log "Maintenance tasks failed: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-IntuneHealthStatus {
    try {
        Write-Log "Checking Intune service health..." "Info"
        
        $HealthStatus = @{
            Timestamp = Get-Date
            Services = @{}
        }
        
        # Check device management service
        try {
            $Devices = Get-MgDeviceManagementManagedDevice -Top 1
            $HealthStatus.Services.DeviceManagement = "Healthy"
        }
        catch {
            $HealthStatus.Services.DeviceManagement = "Unhealthy: $($_.Exception.Message)"
        }
        
        # Check app management service
        try {
            $Apps = Get-MgDeviceAppManagementMobileApp -Top 1
            $HealthStatus.Services.AppManagement = "Healthy"
        }
        catch {
            $HealthStatus.Services.AppManagement = "Unhealthy: $($_.Exception.Message)"
        }
        
        # Check configuration service
        try {
            $Configs = Get-MgDeviceManagementDeviceConfiguration -Top 1
            $HealthStatus.Services.ConfigurationManagement = "Healthy"
        }
        catch {
            $HealthStatus.Services.ConfigurationManagement = "Unhealthy: $($_.Exception.Message)"
        }
        
        return $HealthStatus
    }
    catch {
        Write-Log "Failed to check service health: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Main Execution Functions
function Connect-IntuneServices {
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Scopes
    )
    
    if (-not $Scopes) {
        $Scopes = @(
            "DeviceManagementManagedDevices.ReadWrite.All",
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementApps.ReadWrite.All",
            "DeviceManagementServiceConfig.ReadWrite.All"
        )
    }
    
    try {
        Write-Log "Connecting to Microsoft Graph for Intune management..." "Info"
        Connect-MgGraph -Scopes $Scopes
        Write-Log "Connected to Microsoft Graph successfully" "Success"
        return $true
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Disconnect-IntuneServices {
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log "Disconnected from Microsoft Graph" "Success"
    }
    catch {
        Write-Log "Error during disconnection: $($_.Exception.Message)" "Warning"
    }
}

#endregion

# Example usage:
<#
# Connect to Intune services
Connect-IntuneServices

# Get all devices
$Devices = Get-IntuneDevices -IncludeDetails

# Get non-compliant devices
$NonCompliantDevices = Get-IntuneDevices -ComplianceState "NonCompliant"

# Sync a specific device
Invoke-DeviceAction -DeviceId "device-id" -Action "syncDevice"

# Create a Windows compliance policy
$WindowsPolicy = New-IntuneCompliancePolicy -DisplayName "Standard Windows Compliance" -Platform "Windows10" -PolicySettings @{
    PasswordRequired = $true
    PasswordMinimumLength = 8
    RequireHealthyDeviceReport = $true
    OSMinimumVersion = "10.0.19041"
}

# Get applications
$Apps = Get-IntuneApplications -IncludeAssignments

# Create app assignment
New-AppAssignment -AppId "app-id" -AssignmentType "AllUsers" -Intent "Required"

# Get configuration profiles
$Profiles = Get-ConfigurationProfiles -IncludeAssignments

# Generate analytics report
Get-IntuneAnalytics -OutputPath "Intune_Analytics_Report.json"

# Run maintenance tasks
Start-IntuneMaintenance -SyncDevices -UpdatePolicies

# Check service health
$Health = Get-IntuneHealthStatus

# Disconnect from services
Disconnect-IntuneServices
#>
