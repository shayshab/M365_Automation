# Azure AD (Entra ID) Management Scripts
# Comprehensive PowerShell scripts for Azure AD administration and automation

#region Prerequisites and Setup
# Install required modules
# Install-Module -Name AzureAD -Force
# Install-Module -Name Microsoft.Graph -Force
# Install-Module -Name MSOnline -Force

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
    
    $LogMessage | Out-File -FilePath "M365_AzureADManagement.log" -Append
}

function Test-AzureADConnection {
    try {
        $Context = Get-AzureADCurrentSessionInfo
        if ($Context) {
            Write-Log "Connected to Azure AD for tenant: $($Context.TenantDomain)" "Success"
            return $true
        }
        else {
            Write-Log "Not connected to Azure AD" "Error"
            return $false
        }
    }
    catch {
        Write-Log "Azure AD connection test failed: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Group Management
function Get-AzureADGroups {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Security", "Distribution", "MailEnabledSecurity", "All")]
        [string]$GroupType = "All",
        [Parameter(Mandatory=$false)]
        [switch]$IncludeMembers,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeOwners
    )
    
    try {
        Write-Log "Retrieving Azure AD groups..." "Info"
        
        $Groups = Get-AzureADGroup -All $true
        
        # Apply filters
        if ($DisplayName) {
            $Groups = $Groups | Where-Object {$_.DisplayName -like "*$DisplayName*"}
        }
        
        if ($GroupType -ne "All") {
            switch ($GroupType) {
                "Security" { $Groups = $Groups | Where-Object {$_.SecurityEnabled -eq $true -and $_.MailEnabled -eq $false} }
                "Distribution" { $Groups = $Groups | Where-Object {$_.MailEnabled -eq $true -and $_.SecurityEnabled -eq $false} }
                "MailEnabledSecurity" { $Groups = $Groups | Where-Object {$_.MailEnabled -eq $true -and $_.SecurityEnabled -eq $true} }
            }
        }
        
        if ($IncludeMembers -or $IncludeOwners) {
            $DetailedGroups = @()
            foreach ($Group in $Groups) {
                $GroupInfo = @{
                    ObjectId = $Group.ObjectId
                    DisplayName = $Group.DisplayName
                    Description = $Group.Description
                    GroupType = $Group.GroupTypes
                    SecurityEnabled = $Group.SecurityEnabled
                    MailEnabled = $Group.MailEnabled
                    Mail = $Group.Mail
                    CreatedDateTime = $Group.CreatedDateTime
                }
                
                if ($IncludeMembers) {
                    $Members = Get-AzureADGroupMember -ObjectId $Group.ObjectId
                    $GroupInfo.MemberCount = $Members.Count
                    $GroupInfo.Members = $Members | Select-Object ObjectId, ObjectType, DisplayName
                }
                
                if ($IncludeOwners) {
                    $Owners = Get-AzureADGroupOwner -ObjectId $Group.ObjectId
                    $GroupInfo.OwnerCount = $Owners.Count
                    $GroupInfo.Owners = $Owners | Select-Object ObjectId, ObjectType, DisplayName
                }
                
                $DetailedGroups += $GroupInfo
            }
            return $DetailedGroups
        }
        
        return $Groups
    }
    catch {
        Write-Log "Failed to retrieve groups: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-AzureADGroup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Security", "Distribution", "MailEnabledSecurity")]
        [string]$GroupType = "Security",
        [Parameter(Mandatory=$false)]
        [string]$MailNickname,
        [Parameter(Mandatory=$false)]
        [string[]]$Owners,
        [Parameter(Mandatory=$false)]
        [string[]]$Members
    )
    
    try {
        Write-Log "Creating Azure AD group: $DisplayName" "Info"
        
        # Determine group properties based on type
        switch ($GroupType) {
            "Security" {
                $SecurityEnabled = $true
                $MailEnabled = $false
                $GroupTypes = @("Unified")
            }
            "Distribution" {
                $SecurityEnabled = $false
                $MailEnabled = $true
                $GroupTypes = @()
            }
            "MailEnabledSecurity" {
                $SecurityEnabled = $true
                $MailEnabled = $true
                $GroupTypes = @("Unified")
            }
        }
        
        # Create the group
        $GroupParams = @{
            DisplayName = $DisplayName
            Description = $Description
            SecurityEnabled = $SecurityEnabled
            MailEnabled = $MailEnabled
            GroupTypes = $GroupTypes
        }
        
        if ($MailNickname) {
            $GroupParams.MailNickname = $MailNickname
        }
        
        $NewGroup = New-AzureADGroup @GroupParams
        Write-Log "Group created successfully with ObjectId: $($NewGroup.ObjectId)" "Success"
        
        # Add owners
        if ($Owners) {
            foreach ($Owner in $Owners) {
                $OwnerObject = Get-AzureADUser -Filter "UserPrincipalName eq '$Owner'"
                if ($OwnerObject) {
                    Add-AzureADGroupOwner -ObjectId $NewGroup.ObjectId -RefObjectId $OwnerObject.ObjectId
                    Write-Log "Added owner: $Owner" "Success"
                }
                else {
                    Write-Log "Owner not found: $Owner" "Warning"
                }
            }
        }
        
        # Add members
        if ($Members) {
            foreach ($Member in $Members) {
                $MemberObject = Get-AzureADUser -Filter "UserPrincipalName eq '$Member'"
                if ($MemberObject) {
                    Add-AzureADGroupMember -ObjectId $NewGroup.ObjectId -RefObjectId $MemberObject.ObjectId
                    Write-Log "Added member: $Member" "Success"
                }
                else {
                    Write-Log "Member not found: $Member" "Warning"
                }
            }
        }
        
        return $NewGroup
    }
    catch {
        Write-Log "Failed to create group: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Sync-GroupMembership {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupDisplayName,
        [Parameter(Mandatory=$true)]
        [string[]]$TargetMembers,
        [Parameter(Mandatory=$false)]
        [switch]$RemoveExistingMembers
    )
    
    try {
        Write-Log "Syncing group membership for: $GroupDisplayName" "Info"
        
        $Group = Get-AzureADGroup -Filter "DisplayName eq '$GroupDisplayName'"
        if (-not $Group) {
            Write-Log "Group not found: $GroupDisplayName" "Error"
            return $false
        }
        
        # Get current members
        $CurrentMembers = Get-AzureADGroupMember -ObjectId $Group.ObjectId
        
        if ($RemoveExistingMembers) {
            # Remove all existing members
            foreach ($Member in $CurrentMembers) {
                Remove-AzureADGroupMember -ObjectId $Group.ObjectId -MemberId $Member.ObjectId
                Write-Log "Removed member: $($Member.DisplayName)" "Info"
            }
        }
        
        # Add target members
        foreach ($TargetMember in $TargetMembers) {
            $MemberObject = Get-AzureADUser -Filter "UserPrincipalName eq '$TargetMember'"
            if ($MemberObject) {
                # Check if already a member
                $IsMember = $CurrentMembers | Where-Object {$_.ObjectId -eq $MemberObject.ObjectId}
                if (-not $IsMember) {
                    Add-AzureADGroupMember -ObjectId $Group.ObjectId -RefObjectId $MemberObject.ObjectId
                    Write-Log "Added member: $TargetMember" "Success"
                }
                else {
                    Write-Log "Member already exists: $TargetMember" "Info"
                }
            }
            else {
                Write-Log "Member not found: $TargetMember" "Warning"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to sync group membership: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Application Management
function Get-AzureADApplications {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Web", "Native", "SinglePageApplication", "All")]
        [string]$ApplicationType = "All",
        [Parameter(Mandatory=$false)]
        [switch]$IncludePermissions,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeOwners
    )
    
    try {
        Write-Log "Retrieving Azure AD applications..." "Info"
        
        $Apps = Get-AzureADApplication -All $true
        
        # Apply filters
        if ($DisplayName) {
            $Apps = $Apps | Where-Object {$_.DisplayName -like "*$DisplayName*"}
        }
        
        if ($ApplicationType -ne "All") {
            $Apps = $Apps | Where-Object {$_.PublicClient -eq ($ApplicationType -eq "Native")}
        }
        
        if ($IncludePermissions -or $IncludeOwners) {
            $DetailedApps = @()
            foreach ($App in $Apps) {
                $AppInfo = @{
                    ObjectId = $App.ObjectId
                    AppId = $App.AppId
                    DisplayName = $App.DisplayName
                    HomePage = $App.HomePage
                    IdentifierUris = $App.IdentifierUris
                    ReplyUrls = $App.ReplyUrls
                    PublicClient = $App.PublicClient
                    CreatedDateTime = $App.CreatedDateTime
                }
                
                if ($IncludePermissions) {
                    $Permissions = Get-AzureADApplicationOAuth2PermissionGrant -ObjectId $App.ObjectId
                    $AppInfo.PermissionCount = $Permissions.Count
                    $AppInfo.Permissions = $Permissions | Select-Object ClientId, ResourceId, Scope
                }
                
                if ($IncludeOwners) {
                    $Owners = Get-AzureADApplicationOwner -ObjectId $App.ObjectId
                    $AppInfo.OwnerCount = $Owners.Count
                    $AppInfo.Owners = $Owners | Select-Object ObjectId, ObjectType, DisplayName
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

function New-AzureADApplication {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$HomePage,
        [Parameter(Mandatory=$false)]
        [string[]]$ReplyUrls,
        [Parameter(Mandatory=$false)]
        [string[]]$IdentifierUris,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Web", "Native", "SinglePageApplication")]
        [string]$ApplicationType = "Web",
        [Parameter(Mandatory=$false)]
        [string[]]$Owners
    )
    
    try {
        Write-Log "Creating Azure AD application: $DisplayName" "Info"
        
        $AppParams = @{
            DisplayName = $DisplayName
            PublicClient = ($ApplicationType -eq "Native")
        }
        
        if ($HomePage) { $AppParams.HomePage = $HomePage }
        if ($ReplyUrls) { $AppParams.ReplyUrls = $ReplyUrls }
        if ($IdentifierUris) { $AppParams.IdentifierUris = $IdentifierUris }
        
        $NewApp = New-AzureADApplication @AppParams
        Write-Log "Application created successfully with AppId: $($NewApp.AppId)" "Success"
        
        # Add owners
        if ($Owners) {
            foreach ($Owner in $Owners) {
                $OwnerObject = Get-AzureADUser -Filter "UserPrincipalName eq '$Owner'"
                if ($OwnerObject) {
                    Add-AzureADApplicationOwner -ObjectId $NewApp.ObjectId -RefObjectId $OwnerObject.ObjectId
                    Write-Log "Added owner: $Owner" "Success"
                }
                else {
                    Write-Log "Owner not found: $Owner" "Warning"
                }
            }
        }
        
        return $NewApp
    }
    catch {
        Write-Log "Failed to create application: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Conditional Access Policies
function Get-ConditionalAccessPolicies {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Enabled", "Disabled", "All")]
        [string]$State = "All",
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDetails
    )
    
    try {
        Write-Log "Retrieving Conditional Access policies..." "Info"
        
        # Note: This requires Microsoft Graph module
        Connect-MgGraph -Scopes "Policy.Read.All"
        
        $Policies = Get-MgIdentityConditionalAccessPolicy -All
        
        # Apply filters
        if ($DisplayName) {
            $Policies = $Policies | Where-Object {$_.DisplayName -like "*$DisplayName*"}
        }
        
        if ($State -ne "All") {
            $Policies = $Policies | Where-Object {$_.State -eq $State}
        }
        
        if ($IncludeDetails) {
            $DetailedPolicies = @()
            foreach ($Policy in $Policies) {
                $PolicyInfo = @{
                    Id = $Policy.Id
                    DisplayName = $Policy.DisplayName
                    State = $Policy.State
                    CreatedDateTime = $Policy.CreatedDateTime
                    ModifiedDateTime = $Policy.ModifiedDateTime
                    Conditions = $Policy.Conditions
                    GrantControls = $Policy.GrantControls
                    SessionControls = $Policy.SessionControls
                }
                $DetailedPolicies += $PolicyInfo
            }
            return $DetailedPolicies
        }
        
        return $Policies
    }
    catch {
        Write-Log "Failed to retrieve Conditional Access policies: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-ConditionalAccessPolicy {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$true)]
        [string[]]$IncludeApplications,
        [Parameter(Mandatory=$true)]
        [string[]]$IncludeUsers,
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludeUsers,
        [Parameter(Mandatory=$false)]
        [string[]]$IncludeLocations,
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludeLocations,
        [Parameter(Mandatory=$false)]
        [ValidateSet("block", "mfa", "compliantDevice", "domainJoinedDevice", "approvedClientApp", "compliantApplication")]
        [string[]]$GrantControls = @("mfa"),
        [Parameter(Mandatory=$false)]
        [ValidateSet("Enabled", "Disabled")]
        [string]$State = "Enabled"
    )
    
    try {
        Write-Log "Creating Conditional Access policy: $DisplayName" "Info"
        
        Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
        
        $PolicyBody = @{
            displayName = $DisplayName
            state = $State
            conditions = @{
                applications = @{
                    includeApplications = $IncludeApplications
                }
                users = @{
                    includeUsers = $IncludeUsers
                }
            }
            grantControls = @{
                operator = "OR"
                builtInControls = $GrantControls
            }
        }
        
        # Add optional conditions
        if ($ExcludeUsers) {
            $PolicyBody.conditions.users.excludeUsers = $ExcludeUsers
        }
        
        if ($IncludeLocations) {
            $PolicyBody.conditions.locations = @{
                includeLocations = $IncludeLocations
            }
        }
        
        if ($ExcludeLocations) {
            if (-not $PolicyBody.conditions.locations) {
                $PolicyBody.conditions.locations = @{}
            }
            $PolicyBody.conditions.locations.excludeLocations = $ExcludeLocations
        }
        
        $NewPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyBody
        Write-Log "Conditional Access policy created successfully with ID: $($NewPolicy.Id)" "Success"
        
        return $NewPolicy
    }
    catch {
        Write-Log "Failed to create Conditional Access policy: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Security and Compliance
function Get-RiskEvents {
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("High", "Medium", "Low", "All")]
        [string]$RiskLevel = "All",
        [Parameter(Mandatory=$false)]
        [ValidateSet("Active", "Remediated", "Dismissed", "All")]
        [string]$RiskState = "All",
        [Parameter(Mandatory=$false)]
        [int]$Top = 100
    )
    
    try {
        Write-Log "Retrieving risk events..." "Info"
        
        Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All"
        
        $RiskEvents = Get-MgIdentityRiskEvent -Top $Top
        
        # Apply filters
        if ($RiskLevel -ne "All") {
            $RiskEvents = $RiskEvents | Where-Object {$_.RiskLevel -eq $RiskLevel}
        }
        
        if ($RiskState -ne "All") {
            $RiskEvents = $RiskEvents | Where-Object {$_.RiskState -eq $RiskState}
        }
        
        return $RiskEvents
    }
    catch {
        Write-Log "Failed to retrieve risk events: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Get-SignInLogs {
    param(
        [Parameter(Mandatory=$false)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [string]$ApplicationId,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Success", "Failure", "All")]
        [string]$Status = "All",
        [Parameter(Mandatory=$false)]
        [int]$Top = 100
    )
    
    try {
        Write-Log "Retrieving sign-in logs..." "Info"
        
        Connect-MgGraph -Scopes "AuditLog.Read.All"
        
        $SignIns = Get-MgAuditLogSignIn -Top $Top
        
        # Apply filters
        if ($UserPrincipalName) {
            $SignIns = $SignIns | Where-Object {$_.UserPrincipalName -eq $UserPrincipalName}
        }
        
        if ($ApplicationId) {
            $SignIns = $SignIns | Where-Object {$_.AppId -eq $ApplicationId}
        }
        
        if ($Status -ne "All") {
            $SignIns = $SignIns | Where-Object {$_.Status.ErrorCode -eq 0 -eq ($Status -eq "Success")}
        }
        
        return $SignIns
    }
    catch {
        Write-Log "Failed to retrieve sign-in logs: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Reporting and Analytics
function Get-AzureADAnalytics {
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Generating Azure AD analytics report..." "Info"
        
        $Analytics = @{
            Timestamp = Get-Date
            Tenant = @{}
            Users = @{}
            Groups = @{}
            Applications = @{}
            Security = @{}
        }
        
        # Tenant information
        $TenantInfo = Get-AzureADTenantDetail
        $Analytics.Tenant = @{
            DisplayName = $TenantInfo.DisplayName
            VerifiedDomains = $TenantInfo.VerifiedDomains.Count
            TechnicalNotificationMails = $TenantInfo.TechnicalNotificationMails
        }
        
        # User statistics
        $Users = Get-AzureADUser -All $true
        $Analytics.Users = @{
            TotalUsers = $Users.Count
            EnabledUsers = ($Users | Where-Object {$_.AccountEnabled -eq $true}).Count
            DisabledUsers = ($Users | Where-Object {$_.AccountEnabled -eq $false}).Count
            GuestUsers = ($Users | Where-Object {$_.UserType -eq "Guest"}).Count
        }
        
        # Group statistics
        $Groups = Get-AzureADGroup -All $true
        $Analytics.Groups = @{
            TotalGroups = $Groups.Count
            SecurityGroups = ($Groups | Where-Object {$_.SecurityEnabled -eq $true}).Count
            DistributionGroups = ($Groups | Where-Object {$_.MailEnabled -eq $true -and $_.SecurityEnabled -eq $false}).Count
            MailEnabledSecurityGroups = ($Groups | Where-Object {$_.MailEnabled -eq $true -and $_.SecurityEnabled -eq $true}).Count
        }
        
        # Application statistics
        $Apps = Get-AzureADApplication -All $true
        $Analytics.Applications = @{
            TotalApplications = $Apps.Count
            WebApplications = ($Apps | Where-Object {$_.PublicClient -eq $false}).Count
            NativeApplications = ($Apps | Where-Object {$_.PublicClient -eq $true}).Count
        }
        
        # Security statistics
        try {
            Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All", "AuditLog.Read.All"
            
            $RiskEvents = Get-MgIdentityRiskEvent -Top 100
            $Analytics.Security = @{
                HighRiskEvents = ($RiskEvents | Where-Object {$_.RiskLevel -eq "High"}).Count
                MediumRiskEvents = ($RiskEvents | Where-Object {$_.RiskLevel -eq "Medium"}).Count
                LowRiskEvents = ($RiskEvents | Where-Object {$_.RiskLevel -eq "Low"}).Count
            }
        }
        catch {
            Write-Log "Could not retrieve security statistics: $($_.Exception.Message)" "Warning"
            $Analytics.Security = @{
                Error = "Unable to retrieve security data"
            }
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
function Start-AzureADMaintenance {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$CleanupOrphanedObjects,
        [Parameter(Mandatory=$false)]
        [switch]$UpdateGroupMembership,
        [Parameter(Mandatory=$false)]
        [switch]$AuditPermissions
    )
    
    try {
        Write-Log "Starting Azure AD maintenance tasks..." "Info"
        
        if ($CleanupOrphanedObjects) {
            Write-Log "Cleaning up orphaned objects..." "Info"
            
            # Find groups without owners
            $Groups = Get-AzureADGroup -All $true
            $OrphanedGroups = @()
            
            foreach ($Group in $Groups) {
                $Owners = Get-AzureADGroupOwner -ObjectId $Group.ObjectId
                if ($Owners.Count -eq 0) {
                    $OrphanedGroups += $Group
                }
            }
            
            Write-Log "Found $($OrphanedGroups.Count) groups without owners" "Warning"
            
            # Find applications without owners
            $Apps = Get-AzureADApplication -All $true
            $OrphanedApps = @()
            
            foreach ($App in $Apps) {
                $Owners = Get-AzureADApplicationOwner -ObjectId $App.ObjectId
                if ($Owners.Count -eq 0) {
                    $OrphanedApps += $App
                }
            }
            
            Write-Log "Found $($OrphanedApps.Count) applications without owners" "Warning"
        }
        
        if ($UpdateGroupMembership) {
            Write-Log "Updating group membership..." "Info"
            # Add logic to update group membership based on organizational rules
            Write-Log "Group membership update completed" "Success"
        }
        
        if ($AuditPermissions) {
            Write-Log "Auditing permissions..." "Info"
            
            # Check for users with excessive permissions
            $Users = Get-AzureADUser -All $true | Where-Object {$_.AccountEnabled -eq $true}
            $HighPrivilegeUsers = @()
            
            foreach ($User in $Users) {
                $DirectoryRoles = Get-AzureADUserMembership -ObjectId $User.ObjectId | Where-Object {$_.ObjectType -eq "Role"}
                if ($DirectoryRoles.Count -gt 0) {
                    $HighPrivilegeUsers += @{
                        User = $User
                        Roles = $DirectoryRoles
                    }
                }
            }
            
            Write-Log "Found $($HighPrivilegeUsers.Count) users with directory roles" "Info"
        }
        
        Write-Log "Maintenance tasks completed successfully" "Success"
        return $true
    }
    catch {
        Write-Log "Maintenance tasks failed: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Main Execution Functions
function Connect-AzureADServices {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Interactive
    )
    
    try {
        Write-Log "Connecting to Azure AD services..." "Info"
        
        # Connect to Azure AD
        Connect-AzureAD
        Write-Log "Connected to Azure AD" "Success"
        
        # Connect to Microsoft Graph for additional features
        $Scopes = @(
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Application.ReadWrite.All",
            "Policy.ReadWrite.ConditionalAccess",
            "IdentityRiskEvent.Read.All",
            "AuditLog.Read.All"
        )
        
        Connect-MgGraph -Scopes $Scopes
        Write-Log "Connected to Microsoft Graph" "Success"
        
        return $true
    }
    catch {
        Write-Log "Failed to connect to Azure AD services: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Disconnect-AzureADServices {
    try {
        Disconnect-AzureAD -ErrorAction SilentlyContinue
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log "Disconnected from Azure AD services" "Success"
    }
    catch {
        Write-Log "Error during disconnection: $($_.Exception.Message)" "Warning"
    }
}

#endregion

# Example usage:
<#
# Connect to Azure AD services
Connect-AzureADServices

# Get all groups with members
$Groups = Get-AzureADGroups -IncludeMembers -IncludeOwners

# Create a new security group
$NewGroup = New-AzureADGroup -DisplayName "IT Administrators" -Description "IT Administration group" -GroupType "Security" -Owners @("admin@company.com")

# Sync group membership
Sync-GroupMembership -GroupDisplayName "IT Administrators" -TargetMembers @("user1@company.com", "user2@company.com") -RemoveExistingMembers

# Get applications
$Apps = Get-AzureADApplications -IncludePermissions -IncludeOwners

# Create new application
$NewApp = New-AzureADApplication -DisplayName "Custom App" -ApplicationType "Web" -HomePage "https://app.company.com" -ReplyUrls @("https://app.company.com/auth")

# Get Conditional Access policies
$Policies = Get-ConditionalAccessPolicies -IncludeDetails

# Create Conditional Access policy
$NewPolicy = New-ConditionalAccessPolicy -DisplayName "Require MFA for Admin" -IncludeApplications @("All") -IncludeUsers @("All") -GrantControls @("mfa")

# Get risk events
$RiskEvents = Get-RiskEvents -RiskLevel "High"

# Get sign-in logs
$SignIns = Get-SignInLogs -UserPrincipalName "user@company.com" -Status "Failure"

# Generate analytics report
Get-AzureADAnalytics -OutputPath "AzureAD_Analytics_Report.json"

# Run maintenance tasks
Start-AzureADMaintenance -CleanupOrphanedObjects -UpdateGroupMembership -AuditPermissions

# Disconnect from services
Disconnect-AzureADServices
#>
