# Microsoft Intune Management

## What is Microsoft Intune?

Microsoft Intune is a cloud-based endpoint management solution that helps you manage and protect your organization's devices, applications, and data.

## Key Features

### Device Management
- **Mobile Device Management (MDM)**: Manage Windows, iOS, Android, and macOS devices
- **Mobile Application Management (MAM)**: Manage applications without device enrollment
- **Windows Autopilot**: Automated device deployment and configuration
- **Co-management**: Integration with Configuration Manager

### Application Management
- **App Deployment**: Deploy and manage applications across devices
- **App Protection Policies**: Protect data within applications
- **App Configuration**: Configure application settings
- **App Compliance**: Ensure applications meet security requirements

### Configuration Management
- **Configuration Profiles**: Apply settings to devices
- **Compliance Policies**: Ensure devices meet security requirements
- **Endpoint Security**: Advanced threat protection and security policies
- **Windows Update for Business**: Manage Windows updates

## Device Management

### Basic Device Operations

#### Get Managed Devices
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All"

# Get all managed devices
Get-MgDeviceManagementManagedDevice

# Get devices by compliance state
$NonCompliantDevices = Get-MgDeviceManagementManagedDevice | Where-Object {$_.ComplianceState -eq "NonCompliant"}

# Get device details
$Device = Get-MgDeviceManagementManagedDevice -ManagedDeviceId "device-id"
```

#### Device Actions
```powershell
# Sync device
Send-MgDeviceManagementManagedDeviceSyncDevice -ManagedDeviceId "device-id"

# Retire device
Invoke-MgRetireDeviceManagementManagedDevice -ManagedDeviceId "device-id"

# Wipe device
Invoke-MgWipeDeviceManagementManagedDevice -ManagedDeviceId "device-id"

# Remote lock
Invoke-MgRemoteLockDeviceManagementManagedDevice -ManagedDeviceId "device-id"

# Reset passcode (iOS)
Invoke-MgResetPasscodeDeviceManagementManagedDevice -ManagedDeviceId "device-id"
```

### Compliance Policies

#### Create Windows Compliance Policy
```powershell
$CompliancePolicy = @{
    "@odata.type" = "#microsoft.graph.windows10CompliancePolicy"
    displayName = "Windows 10 Compliance Policy"
    description = "Standard compliance policy for Windows 10"
    passwordRequired = $true
    passwordMinimumLength = 8
    passwordRequiredType = "alphanumeric"
    passwordExpirationDays = 90
    passwordMinutesOfInactivityBeforeLock = 15
    requireHealthyDeviceReport = $true
    osMinimumVersion = "10.0.19041"
    osMaximumVersion = "10.0.19045"
    storageRequireEncryption = $true
    securityRequireTpm = $true
}

New-MgDeviceManagementDeviceCompliancePolicy -BodyParameter $CompliancePolicy
```

#### Create iOS Compliance Policy
```powershell
$iOSCompliancePolicy = @{
    "@odata.type" = "#microsoft.graph.iosCompliancePolicy"
    displayName = "iOS Compliance Policy"
    description = "Standard compliance policy for iOS devices"
    passcodeRequired = $true
    passcodeMinimumLength = 6
    passcodeMinutesOfInactivityBeforeLock = 5
    osMinimumVersion = "15.0"
    osMaximumVersion = "17.0"
    storageRequireEncryption = $true
    managedEmailProfileRequired = $true
}

New-MgDeviceManagementDeviceCompliancePolicy -BodyParameter $iOSCompliancePolicy
```

## Application Management

### App Deployment

#### Get Applications
```powershell
# Get all applications
$Apps = Get-MgDeviceAppManagementMobileApp

# Get Windows applications
$WindowsApps = $Apps | Where-Object {$_.'@odata.type' -like "*windows*"}

# Get iOS applications
$iOSApps = $Apps | Where-Object {$_.'@odata.type' -like "*ios*"}
```

#### Create App Assignment
```powershell
# Create app assignment for all users
$AppAssignment = @{
    "@odata.type" = "#microsoft.graph.mobileAppAssignment"
    intent = "Required"
    target = @{
        "@odata.type" = "#microsoft.graph.allLicensedUsersAssignmentTarget"
    }
}

New-MgDeviceAppManagementMobileAppAssignment -MobileAppId "app-id" -BodyParameter $AppAssignment

# Create app assignment for specific group
$AppAssignment = @{
    "@odata.type" = "#microsoft.graph.mobileAppAssignment"
    intent = "Required"
    target = @{
        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
        groupId = "group-id"
    }
}
```

### App Protection Policies

#### Create App Protection Policy
```powershell
$AppProtectionPolicy = @{
    "@odata.type" = "#microsoft.graph.iosManagedAppProtection"
    displayName = "iOS App Protection Policy"
    description = "Protection policy for iOS apps"
    appDataEncryptionType = "whenDeviceLocked"
    screenCaptureBlocked = $true
    disableAppPinIfDevicePinIsSet = $true
    minimumRequiredOsVersion = "15.0"
    minimumWarningOsVersion = "15.0"
    minimumRequiredAppVersion = "1.0"
    minimumWarningAppVersion = "1.0"
}

New-MgDeviceAppManagementiOSManagedAppProtection -BodyParameter $AppProtectionPolicy
```

## Configuration Profiles

### Windows Configuration Profiles

#### Create Windows Configuration Profile
```powershell
$ConfigProfile = @{
    "@odata.type" = "#microsoft.graph.windows10GeneralConfiguration"
    displayName = "Windows 10 Standard Configuration"
    description = "Standard configuration for Windows 10 devices"
    passwordBlockSimple = $true
    passwordRequired = $true
    passwordMinimumLength = 8
    passwordMinimumCharacterSetCount = 3
    passwordRequiredType = "alphanumeric"
    passwordExpirationDays = 90
    passwordMinutesOfInactivityBeforeScreenTimeout = 15
    passwordPreviousPasswordBlockCount = 5
    requireHealthyDeviceReport = $true
    defenderEnabled = $true
    defenderScanType = "userDefined"
    defenderScheduleScanDay = "everyday"
    defenderScheduleScanTime = "02:00:00.0000000"
}

New-MgDeviceManagementDeviceConfiguration -BodyParameter $ConfigProfile
```

#### Create Wi-Fi Configuration Profile
```powershell
$WiFiConfig = @{
    "@odata.type" = "#microsoft.graph.windowsWifiConfiguration"
    displayName = "Corporate WiFi"
    description = "Corporate WiFi configuration"
    ssid = "CorporateWiFi"
    networkName = "CorporateWiFi"
    wifiSecurityType = "wpa2Enterprise"
    connectAutomatically = $true
    connectWhenNetworkNameIsHidden = $true
    proxySettings = "none"
}

New-MgDeviceManagementDeviceConfiguration -BodyParameter $WiFiConfig
```

## Reporting and Analytics

### Device Compliance Report
```powershell
function Get-DeviceComplianceReport {
    $Devices = Get-MgDeviceManagementManagedDevice -All
    
    $Report = @{
        TotalDevices = $Devices.Count
        CompliantDevices = ($Devices | Where-Object {$_.ComplianceState -eq "Compliant"}).Count
        NonCompliantDevices = ($Devices | Where-Object {$_.ComplianceState -eq "NonCompliant"}).Count
        InGracePeriod = ($Devices | Where-Object {$_.ComplianceState -eq "InGracePeriod"}).Count
        ErrorDevices = ($Devices | Where-Object {$_.ComplianceState -eq "Error"}).Count
        PlatformBreakdown = $Devices | Group-Object DeviceType | ForEach-Object {
            @{
                Platform = $_.Name
                Count = $_.Count
                Percentage = [math]::Round(($_.Count / $Devices.Count) * 100, 2)
            }
        }
    }
    
    return $Report
}
```

### Application Deployment Report
```powershell
function Get-AppDeploymentReport {
    $Apps = Get-MgDeviceAppManagementMobileApp -All
    
    $Report = @{
        TotalApps = $Apps.Count
        WindowsApps = ($Apps | Where-Object {$_.'@odata.type' -like "*windows*"}).Count
        iOSApps = ($Apps | Where-Object {$_.'@odata.type' -like "*ios*"}).Count
        AndroidApps = ($Apps | Where-Object {$_.'@odata.type' -like "*android*"}).Count
        macOSApps = ($Apps | Where-Object {$_.'@odata.type' -like "*macos*"}).Count
    }
    
    return $Report
}
```

## Automation and Maintenance

### Automated Device Management
```powershell
function Start-IntuneMaintenance {
    # Get non-compliant devices
    $NonCompliantDevices = Get-MgDeviceManagementManagedDevice | Where-Object {$_.ComplianceState -eq "NonCompliant"}
    
    foreach ($Device in $NonCompliantDevices) {
        Write-Host "Processing non-compliant device: $($Device.DeviceName)" -ForegroundColor Yellow
        
        # Send sync command
        Send-MgDeviceManagementManagedDeviceSyncDevice -ManagedDeviceId $Device.Id
        
        # Send notification
        Send-MgDeviceManagementManagedDeviceNotification -ManagedDeviceId $Device.Id -NotificationType "complianceCheckIn"
    }
    
    Write-Host "Maintenance completed for $($NonCompliantDevices.Count) devices" -ForegroundColor Green
}
```

### Policy Enforcement
```powershell
function Enforce-SecurityPolicies {
    # Get devices with outdated policies
    $Devices = Get-MgDeviceManagementManagedDevice -All
    
    foreach ($Device in $Devices) {
        if ($Device.LastSyncDateTime -lt (Get-Date).AddHours(-24)) {
            Write-Host "Device $($Device.DeviceName) hasn't synced in 24+ hours" -ForegroundColor Yellow
            Send-MgDeviceManagementManagedDeviceSyncDevice -ManagedDeviceId $Device.Id
        }
    }
}
```

## Best Practices

### Device Management
1. Use consistent naming conventions
2. Implement proper compliance policies
3. Regular device health monitoring
4. Automated remediation for non-compliance

### Application Management
1. Use app protection policies
2. Regular app updates and patches
3. Monitor app usage and compliance
4. Implement app whitelisting where appropriate

### Security
1. Enable endpoint security features
2. Regular security policy updates
3. Monitor for security threats
4. Implement data loss prevention

### Monitoring
1. Set up automated reporting
2. Monitor device compliance trends
3. Track application deployment success
4. Regular policy effectiveness reviews

---

*This guide covers Microsoft Intune device and application management. For advanced scenarios and integration with other M365 services, refer to the service-specific documentation.*
