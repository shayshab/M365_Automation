# M365 User Management Scripts
# Comprehensive PowerShell scripts for user lifecycle management

#region Prerequisites and Setup
# Install required modules
# Install-Module -Name Microsoft.Graph -Force
# Install-Module -Name AzureAD -Force
# Install-Module -Name ExchangeOnlineManagement -Force

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
    
    # Also write to log file
    $LogMessage | Out-File -FilePath "M365_UserManagement.log" -Append
}

function Test-M365Connections {
    Write-Log "Testing M365 service connections..." "Info"
    
    $Results = @{
        AzureAD = $false
        GraphAPI = $false
        Exchange = $false
    }
    
    # Test Azure AD connection
    try {
        $Context = Get-AzureADCurrentSessionInfo -ErrorAction Stop
        if ($Context) {
            $Results.AzureAD = $true
            Write-Log "Azure AD connection: Connected to $($Context.TenantDomain)" "Success"
        }
    }
    catch {
        Write-Log "Azure AD connection failed: $($_.Exception.Message)" "Error"
    }
    
    # Test Graph API connection
    try {
        $Context = Get-MgContext -ErrorAction Stop
        if ($Context) {
            $Results.GraphAPI = $true
            Write-Log "Graph API connection: Connected to $($Context.TenantId)" "Success"
        }
    }
    catch {
        Write-Log "Graph API connection failed: $($_.Exception.Message)" "Error"
    }
    
    # Test Exchange connection
    try {
        $Session = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange"}
        if ($Session) {
            $Results.Exchange = $true
            Write-Log "Exchange connection: Active session found" "Success"
        }
    }
    catch {
        Write-Log "Exchange connection failed: $($_.Exception.Message)" "Error"
    }
    
    return $Results
}

#endregion

#region User Creation and Management
function New-M365User {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$true)]
        [string]$Department,
        [Parameter(Mandatory=$true)]
        [string]$JobTitle,
        [Parameter(Mandatory=$false)]
        [string]$ManagerEmail,
        [Parameter(Mandatory=$false)]
        [string]$OfficeLocation,
        [Parameter(Mandatory=$false)]
        [string]$PhoneNumber,
        [Parameter(Mandatory=$false)]
        [string]$LicenseSku = "ENTERPRISEPACK"
    )
    
    try {
        Write-Log "Creating new user: $DisplayName ($UserPrincipalName)" "Info"
        
        # Generate temporary password
        $TempPassword = [System.Web.Security.Membership]::GeneratePassword(12, 4)
        
        # Create password profile
        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        $PasswordProfile.Password = $TempPassword
        $PasswordProfile.ForceChangePasswordNextLogin = $true
        
        # Create user object
        $UserParams = @{
            DisplayName = $DisplayName
            UserPrincipalName = $UserPrincipalName
            PasswordProfile = $PasswordProfile
            AccountEnabled = $true
            JobTitle = $JobTitle
            Department = $Department
        }
        
        # Add optional parameters
        if ($OfficeLocation) { $UserParams.UsageLocation = "US" }
        if ($PhoneNumber) { $UserParams.TelephoneNumber = $PhoneNumber }
        
        # Create the user
        $NewUser = New-AzureADUser @UserParams
        Write-Log "User created successfully with ObjectId: $($NewUser.ObjectId)" "Success"
        
        # Assign license
        if ($LicenseSku) {
            $AccountSku = Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq $LicenseSku}
            if ($AccountSku) {
                Set-AzureADUserLicense -ObjectId $NewUser.ObjectId -AssignedLicenses @{SkuId = $AccountSku.SkuId}
                Write-Log "License $LicenseSku assigned to user" "Success"
            }
        }
        
        # Set manager if provided
        if ($ManagerEmail) {
            $Manager = Get-AzureADUser -Filter "UserPrincipalName eq '$ManagerEmail'"
            if ($Manager) {
                Set-AzureADUserManager -ObjectId $NewUser.ObjectId -RefObjectId $Manager.ObjectId
                Write-Log "Manager set to $ManagerEmail" "Success"
            }
        }
        
        # Add to department group
        $DepartmentGroup = Get-AzureADGroup -Filter "DisplayName eq '$Department'"
        if ($DepartmentGroup) {
            Add-AzureADGroupMember -ObjectId $DepartmentGroup.ObjectId -RefObjectId $NewUser.ObjectId
            Write-Log "User added to department group: $Department" "Success"
        }
        
        return @{
            User = $NewUser
            TemporaryPassword = $TempPassword
            Success = $true
        }
    }
    catch {
        Write-Log "Failed to create user: $($_.Exception.Message)" "Error"
        return @{
            User = $null
            TemporaryPassword = $null
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function New-BulkUsers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CSVPath
    )
    
    if (-not (Test-Path $CSVPath)) {
        Write-Log "CSV file not found: $CSVPath" "Error"
        return
    }
    
    $Users = Import-Csv -Path $CSVPath
    $Results = @()
    
    Write-Log "Starting bulk user creation for $($Users.Count) users" "Info"
    
    foreach ($User in $Users) {
        $Result = New-M365User -DisplayName $User.DisplayName `
                              -UserPrincipalName $User.UserPrincipalName `
                              -Department $User.Department `
                              -JobTitle $User.JobTitle `
                              -ManagerEmail $User.ManagerEmail `
                              -OfficeLocation $User.OfficeLocation `
                              -PhoneNumber $User.PhoneNumber `
                              -LicenseSku $User.LicenseSku
        
        $Results += @{
            UserPrincipalName = $User.UserPrincipalName
            Success = $Result.Success
            TemporaryPassword = $Result.TemporaryPassword
            Error = $Result.Error
        }
        
        # Add delay to avoid throttling
        Start-Sleep -Seconds 2
    }
    
    # Export results
    $Results | Export-Csv -Path "BulkUserCreation_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
    Write-Log "Bulk user creation completed. Results exported to CSV." "Success"
    
    return $Results
}

#endregion

#region User Modification and Updates
function Update-UserProperties {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [hashtable]$Properties
    )
    
    try {
        $User = Get-AzureADUser -Filter "UserPrincipalName eq '$UserPrincipalName'"
        if (-not $User) {
            Write-Log "User not found: $UserPrincipalName" "Error"
            return $false
        }
        
        Write-Log "Updating properties for user: $UserPrincipalName" "Info"
        
        # Update properties
        foreach ($Property in $Properties.GetEnumerator()) {
            Set-AzureADUser -ObjectId $User.ObjectId -$($Property.Key) $Property.Value
            Write-Log "Updated $($Property.Key): $($Property.Value)" "Success"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to update user properties: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Move-UserToDepartment {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$true)]
        [string]$NewDepartment,
        [Parameter(Mandatory=$false)]
        [string]$OldDepartment
    )
    
    try {
        $User = Get-AzureADUser -Filter "UserPrincipalName eq '$UserPrincipalName'"
        if (-not $User) {
            Write-Log "User not found: $UserPrincipalName" "Error"
            return $false
        }
        
        # Remove from old department group
        if ($OldDepartment) {
            $OldGroup = Get-AzureADGroup -Filter "DisplayName eq '$OldDepartment'"
            if ($OldGroup) {
                Remove-AzureADGroupMember -ObjectId $OldGroup.ObjectId -MemberId $User.ObjectId
                Write-Log "Removed from old department group: $OldDepartment" "Success"
            }
        }
        
        # Add to new department group
        $NewGroup = Get-AzureADGroup -Filter "DisplayName eq '$NewDepartment'"
        if ($NewGroup) {
            Add-AzureADGroupMember -ObjectId $NewGroup.ObjectId -RefObjectId $User.ObjectId
            Write-Log "Added to new department group: $NewDepartment" "Success"
        }
        
        # Update department property
        Set-AzureADUser -ObjectId $User.ObjectId -Department $NewDepartment
        Write-Log "Updated department property to: $NewDepartment" "Success"
        
        return $true
    }
    catch {
        Write-Log "Failed to move user to department: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region License Management
function Set-UserLicense {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$true)]
        [string]$LicenseSku,
        [Parameter(Mandatory=$false)]
        [switch]$RemoveLicense
    )
    
    try {
        $User = Get-AzureADUser -Filter "UserPrincipalName eq '$UserPrincipalName'"
        if (-not $User) {
            Write-Log "User not found: $UserPrincipalName" "Error"
            return $false
        }
        
        $License = Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq $LicenseSku}
        if (-not $License) {
            Write-Log "License not found: $LicenseSku" "Error"
            return $false
        }
        
        if ($RemoveLicense) {
            # Remove license
            $CurrentLicenses = Get-AzureADUserLicenseDetail -ObjectId $User.ObjectId
            $LicensesToRemove = @{SkuId = $License.SkuId}
            Set-AzureADUserLicense -ObjectId $User.ObjectId -AssignedLicenses @{} -RemoveLicenses $LicensesToRemove
            Write-Log "Removed license $LicenseSku from user" "Success"
        }
        else {
            # Add license
            Set-AzureADUserLicense -ObjectId $User.ObjectId -AssignedLicenses @{SkuId = $License.SkuId}
            Write-Log "Assigned license $LicenseSku to user" "Success"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to manage license: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-LicenseUsage {
    param(
        [Parameter(Mandatory=$false)]
        [string]$LicenseSku
    )
    
    try {
        if ($LicenseSku) {
            $Licenses = Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq $LicenseSku}
        }
        else {
            $Licenses = Get-AzureADSubscribedSku
        }
        
        $UsageReport = @()
        
        foreach ($License in $Licenses) {
            $Usage = @{
                SkuPartNumber = $License.SkuPartNumber
                SkuDisplayName = $License.SkuDisplayName
                ConsumedUnits = $License.ConsumedUnits
                PrepaidUnits = $License.PrepaidUnits.Enabled
                AvailableUnits = $License.PrepaidUnits.Enabled - $License.ConsumedUnits
                UsagePercentage = [math]::Round(($License.ConsumedUnits / $License.PrepaidUnits.Enabled) * 100, 2)
            }
            $UsageReport += $Usage
        }
        
        return $UsageReport
    }
    catch {
        Write-Log "Failed to get license usage: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region User Deactivation and Cleanup
function Disable-UserAccount {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [switch]$RemoveLicenses,
        [Parameter(Mandatory=$false)]
        [switch]$ConvertToSharedMailbox
    )
    
    try {
        $User = Get-AzureADUser -Filter "UserPrincipalName eq '$UserPrincipalName'"
        if (-not $User) {
            Write-Log "User not found: $UserPrincipalName" "Error"
            return $false
        }
        
        Write-Log "Disabling user account: $UserPrincipalName" "Info"
        
        # Remove licenses if requested
        if ($RemoveLicenses) {
            $CurrentLicenses = Get-AzureADUserLicenseDetail -ObjectId $User.ObjectId
            if ($CurrentLicenses) {
                $LicensesToRemove = @{}
                foreach ($License in $CurrentLicenses) {
                    $LicensesToRemove.Add($License.SkuId, $License.SkuId)
                }
                Set-AzureADUserLicense -ObjectId $User.ObjectId -AssignedLicenses @{} -RemoveLicenses $LicensesToRemove
                Write-Log "Removed all licenses from user" "Success"
            }
        }
        
        # Convert to shared mailbox if requested
        if ($ConvertToSharedMailbox) {
            Connect-ExchangeOnline
            Set-Mailbox -Identity $UserPrincipalName -Type Shared
            Write-Log "Converted mailbox to shared mailbox" "Success"
            Disconnect-ExchangeOnline
        }
        
        # Disable the account
        Set-AzureADUser -ObjectId $User.ObjectId -AccountEnabled $false
        Write-Log "User account disabled successfully" "Success"
        
        return $true
    }
    catch {
        Write-Log "Failed to disable user account: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Remove-UserAccount {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    try {
        $User = Get-AzureADUser -Filter "UserPrincipalName eq '$UserPrincipalName'"
        if (-not $User) {
            Write-Log "User not found: $UserPrincipalName" "Error"
            return $false
        }
        
        if (-not $Force) {
            $Confirmation = Read-Host "Are you sure you want to permanently delete user $UserPrincipalName? (yes/no)"
            if ($Confirmation -ne "yes") {
                Write-Log "User deletion cancelled by user" "Warning"
                return $false
            }
        }
        
        Write-Log "Permanently deleting user account: $UserPrincipalName" "Warning"
        
        # Remove user from all groups first
        $Groups = Get-AzureADUserMembership -ObjectId $User.ObjectId
        foreach ($Group in $Groups) {
            Remove-AzureADGroupMember -ObjectId $Group.ObjectId -MemberId $User.ObjectId
        }
        
        # Delete the user
        Remove-AzureADUser -ObjectId $User.ObjectId
        Write-Log "User account permanently deleted" "Success"
        
        return $true
    }
    catch {
        Write-Log "Failed to delete user account: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Reporting and Analytics
function Get-UserReport {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Department,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeInactive,
        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Generating user report..." "Info"
        
        $Filter = "AccountEnabled eq true"
        if ($IncludeInactive) {
            $Filter = "AccountEnabled eq true or AccountEnabled eq false"
        }
        
        $Users = Get-AzureADUser -Filter $Filter -All $true
        
        if ($Department) {
            $Users = $Users | Where-Object {$_.Department -eq $Department}
        }
        
        $Report = @()
        
        foreach ($User in $Users) {
            # Get user's groups
            $Groups = Get-AzureADUserMembership -ObjectId $User.ObjectId | Where-Object {$_.ObjectType -eq "Group"}
            $GroupNames = ($Groups | Select-Object -ExpandProperty DisplayName) -join ", "
            
            # Get user's licenses
            $Licenses = Get-AzureADUserLicenseDetail -ObjectId $User.ObjectId
            $LicenseNames = ($Licenses | Select-Object -ExpandProperty SkuDisplayName) -join ", "
            
            $UserInfo = @{
                DisplayName = $User.DisplayName
                UserPrincipalName = $User.UserPrincipalName
                Department = $User.Department
                JobTitle = $User.JobTitle
                OfficeLocation = $User.OfficeLocation
                PhoneNumber = $User.TelephoneNumber
                AccountEnabled = $User.AccountEnabled
                LastSignIn = $User.SignInNames
                Groups = $GroupNames
                Licenses = $LicenseNames
                CreatedDate = $User.CreationType
            }
            
            $Report += $UserInfo
        }
        
        if ($OutputPath) {
            $Report | Export-Csv -Path $OutputPath -NoTypeInformation
            Write-Log "User report exported to: $OutputPath" "Success"
        }
        
        return $Report
    }
    catch {
        Write-Log "Failed to generate user report: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Main Execution Functions
function Connect-M365Services {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Interactive
    )
    
    Write-Log "Connecting to M365 services..." "Info"
    
    try {
        # Connect to Azure AD
        Connect-AzureAD
        Write-Log "Connected to Azure AD" "Success"
        
        # Connect to Graph API
        $Scopes = @(
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Directory.ReadWrite.All"
        )
        Connect-MgGraph -Scopes $Scopes
        Write-Log "Connected to Microsoft Graph API" "Success"
        
        # Connect to Exchange Online
        Connect-ExchangeOnline
        Write-Log "Connected to Exchange Online" "Success"
        
        return $true
    }
    catch {
        Write-Log "Failed to connect to M365 services: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Disconnect-M365Services {
    Write-Log "Disconnecting from M365 services..." "Info"
    
    try {
        Disconnect-AzureAD -ErrorAction SilentlyContinue
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        
        Write-Log "Disconnected from all M365 services" "Success"
    }
    catch {
        Write-Log "Error during disconnection: $($_.Exception.Message)" "Warning"
    }
}

#endregion

# Example usage:
<#
# Connect to services
Connect-M365Services

# Create a single user
$NewUser = New-M365User -DisplayName "John Doe" -UserPrincipalName "john.doe@company.com" -Department "IT" -JobTitle "System Administrator"

# Create users from CSV
New-BulkUsers -CSVPath "C:\Users.csv"

# Update user properties
Update-UserProperties -UserPrincipalName "john.doe@company.com" -Properties @{
    JobTitle = "Senior System Administrator"
    OfficeLocation = "New York"
}

# Move user to different department
Move-UserToDepartment -UserPrincipalName "john.doe@company.com" -NewDepartment "Engineering" -OldDepartment "IT"

# Manage licenses
Set-UserLicense -UserPrincipalName "john.doe@company.com" -LicenseSku "ENTERPRISEPACK"
Get-LicenseUsage

# Disable user account
Disable-UserAccount -UserPrincipalName "john.doe@company.com" -RemoveLicenses -ConvertToSharedMailbox

# Generate reports
Get-UserReport -Department "IT" -OutputPath "IT_Users_Report.csv"

# Disconnect from services
Disconnect-M365Services
#>
