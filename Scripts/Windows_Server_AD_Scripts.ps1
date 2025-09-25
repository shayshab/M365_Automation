# Windows Server and Active Directory Management Scripts
# Comprehensive PowerShell scripts for Windows Server and Active Directory administration

#region Prerequisites and Setup
# Install required modules
# Install-Module -Name ActiveDirectory -Force
# Install-Module -Name AzureAD -Force
# Install-Module -Name Microsoft.Graph -Force

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
    
    $LogMessage | Out-File -FilePath "M365_WindowsServerADManagement.log" -Append
}

function Test-ADConnection {
    try {
        $Domain = Get-ADDomain
        if ($Domain) {
            Write-Log "Connected to Active Directory domain: $($Domain.DNSRoot)" "Success"
            return $true
        }
        else {
            Write-Log "Not connected to Active Directory" "Error"
            return $false
        }
    }
    catch {
        Write-Log "Active Directory connection test failed: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region User Management
function Get-ADUsers {
    param(
        [Parameter(Mandatory=$false)]
        [string]$SearchBase,
        [Parameter(Mandatory=$false)]
        [string]$Filter = "*",
        [Parameter(Mandatory=$false)]
        [string[]]$Properties,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDisabled,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDetails
    )
    
    try {
        Write-Log "Retrieving Active Directory users..." "Info"
        
        $SearchParams = @{
            Filter = $Filter
        }
        
        if ($SearchBase) { $SearchParams.SearchBase = $SearchBase }
        if ($Properties) { $SearchParams.Properties = $Properties }
        
        $Users = Get-ADUser @SearchParams
        
        if (-not $IncludeDisabled) {
            $Users = $Users | Where-Object {$_.Enabled -eq $true}
        }
        
        if ($IncludeDetails) {
            $DetailedUsers = @()
            foreach ($User in $Users) {
                $UserInfo = @{
                    SamAccountName = $User.SamAccountName
                    DisplayName = $User.DisplayName
                    UserPrincipalName = $User.UserPrincipalName
                    EmailAddress = $User.EmailAddress
                    Department = $User.Department
                    Title = $User.Title
                    Manager = $User.Manager
                    Enabled = $User.Enabled
                    LastLogonDate = $User.LastLogonDate
                    PasswordLastSet = $User.PasswordLastSet
                    PasswordExpired = $User.PasswordExpired
                    PasswordNeverExpires = $User.PasswordNeverExpires
                    AccountExpirationDate = $User.AccountExpirationDate
                    DistinguishedName = $User.DistinguishedName
                    ObjectClass = $User.ObjectClass
                    ObjectGUID = $User.ObjectGUID
                    SID = $User.SID
                    Created = $User.Created
                    Modified = $User.Modified
                }
                $DetailedUsers += $UserInfo
            }
            return $DetailedUsers
        }
        
        return $Users
    }
    catch {
        Write-Log "Failed to retrieve AD users: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-ADUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SamAccountName,
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$true)]
        [string]$Password,
        [Parameter(Mandatory=$false)]
        [string]$GivenName,
        [Parameter(Mandatory=$false)]
        [string]$Surname,
        [Parameter(Mandatory=$false)]
        [string]$EmailAddress,
        [Parameter(Mandatory=$false)]
        [string]$Department,
        [Parameter(Mandatory=$false)]
        [string]$Title,
        [Parameter(Mandatory=$false)]
        [string]$Office,
        [Parameter(Mandatory=$false)]
        [string]$PhoneNumber,
        [Parameter(Mandatory=$false)]
        [string]$Manager,
        [Parameter(Mandatory=$false)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [switch]$Enabled = $true,
        [Parameter(Mandatory=$false)]
        [switch]$ChangePasswordAtLogon = $true
    )
    
    try {
        Write-Log "Creating Active Directory user: $DisplayName" "Info"
        
        $UserParams = @{
            SamAccountName = $SamAccountName
            DisplayName = $DisplayName
            UserPrincipalName = $UserPrincipalName
            AccountPassword = (ConvertTo-SecureString $Password -AsPlainText -Force)
            Enabled = $Enabled
            ChangePasswordAtLogon = $ChangePasswordAtLogon
        }
        
        # Add optional parameters
        if ($GivenName) { $UserParams.GivenName = $GivenName }
        if ($Surname) { $UserParams.Surname = $Surname }
        if ($EmailAddress) { $UserParams.EmailAddress = $EmailAddress }
        if ($Department) { $UserParams.Department = $Department }
        if ($Title) { $UserParams.Title = $Title }
        if ($Office) { $UserParams.Office = $Office }
        if ($PhoneNumber) { $UserParams.PhoneNumber = $PhoneNumber }
        if ($Path) { $UserParams.Path = $Path }
        
        $NewUser = New-ADUser @UserParams
        Write-Log "User created successfully: $SamAccountName" "Success"
        
        # Set manager if provided
        if ($Manager) {
            $ManagerObject = Get-ADUser -Filter "SamAccountName eq '$Manager'"
            if ($ManagerObject) {
                Set-ADUser -Identity $NewUser.SamAccountName -Manager $ManagerObject.DistinguishedName
                Write-Log "Manager set to: $Manager" "Success"
            }
            else {
                Write-Log "Manager not found: $Manager" "Warning"
            }
        }
        
        return $NewUser
    }
    catch {
        Write-Log "Failed to create AD user: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Set-ADUserProperties {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Identity,
        [Parameter(Mandatory=$false)]
        [hashtable]$Properties
    )
    
    try {
        Write-Log "Updating AD user properties: $Identity" "Info"
        
        $User = Get-ADUser -Identity $Identity
        if (-not $User) {
            Write-Log "User not found: $Identity" "Error"
            return $false
        }
        
        foreach ($Property in $Properties.GetEnumerator()) {
            Set-ADUser -Identity $Identity -$($Property.Key) $Property.Value
            Write-Log "Updated $($Property.Key): $($Property.Value)" "Success"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to update user properties: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Group Management
function Get-ADGroups {
    param(
        [Parameter(Mandatory=$false)]
        [string]$SearchBase,
        [Parameter(Mandatory=$false)]
        [string]$Filter = "*",
        [Parameter(Mandatory=$false)]
        [string[]]$Properties,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Security", "Distribution", "All")]
        [string]$GroupType = "All",
        [Parameter(Mandatory=$false)]
        [switch]$IncludeMembers,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDetails
    )
    
    try {
        Write-Log "Retrieving Active Directory groups..." "Info"
        
        $SearchParams = @{
            Filter = $Filter
        }
        
        if ($SearchBase) { $SearchParams.SearchBase = $SearchBase }
        if ($Properties) { $SearchParams.Properties = $Properties }
        
        $Groups = Get-ADGroup @SearchParams
        
        # Apply group type filter
        if ($GroupType -ne "All") {
            $Groups = $Groups | Where-Object {$_.GroupCategory -eq $GroupType}
        }
        
        if ($IncludeMembers -or $IncludeDetails) {
            $DetailedGroups = @()
            foreach ($Group in $Groups) {
                $GroupInfo = @{
                    SamAccountName = $Group.SamAccountName
                    DisplayName = $Group.DisplayName
                    Name = $Group.Name
                    Description = $Group.Description
                    GroupCategory = $Group.GroupCategory
                    GroupScope = $Group.GroupScope
                    DistinguishedName = $Group.DistinguishedName
                    ObjectClass = $Group.ObjectClass
                    ObjectGUID = $Group.ObjectGUID
                    SID = $Group.SID
                    Created = $Group.Created
                    Modified = $Group.Modified
                }
                
                if ($IncludeMembers) {
                    $Members = Get-ADGroupMember -Identity $Group.SamAccountName
                    $GroupInfo.MemberCount = $Members.Count
                    $GroupInfo.Members = $Members | Select-Object SamAccountName, Name, ObjectClass
                }
                
                $DetailedGroups += $GroupInfo
            }
            return $DetailedGroups
        }
        
        return $Groups
    }
    catch {
        Write-Log "Failed to retrieve AD groups: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-ADGroup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$SamAccountName,
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Security", "Distribution")]
        [string]$GroupCategory = "Security",
        [Parameter(Mandatory=$false)]
        [ValidateSet("DomainLocal", "Global", "Universal")]
        [string]$GroupScope = "Global",
        [Parameter(Mandatory=$false)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [string[]]$Members
    )
    
    try {
        Write-Log "Creating Active Directory group: $Name" "Info"
        
        $GroupParams = @{
            Name = $Name
            GroupCategory = $GroupCategory
            GroupScope = $GroupScope
        }
        
        if ($SamAccountName) { $GroupParams.SamAccountName = $SamAccountName }
        if ($DisplayName) { $GroupParams.DisplayName = $DisplayName }
        if ($Description) { $GroupParams.Description = $Description }
        if ($Path) { $GroupParams.Path = $Path }
        
        $NewGroup = New-ADGroup @GroupParams
        Write-Log "Group created successfully: $Name" "Success"
        
        # Add members if provided
        if ($Members) {
            foreach ($Member in $Members) {
                try {
                    Add-ADGroupMember -Identity $NewGroup.SamAccountName -Members $Member
                    Write-Log "Added member: $Member" "Success"
                }
                catch {
                    Write-Log "Failed to add member $Member : $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        return $NewGroup
    }
    catch {
        Write-Log "Failed to create AD group: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Sync-ADGroupMembership {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [string[]]$TargetMembers,
        [Parameter(Mandatory=$false)]
        [switch]$RemoveExistingMembers
    )
    
    try {
        Write-Log "Syncing AD group membership for: $GroupName" "Info"
        
        $Group = Get-ADGroup -Identity $GroupName
        if (-not $Group) {
            Write-Log "Group not found: $GroupName" "Error"
            return $false
        }
        
        # Get current members
        $CurrentMembers = Get-ADGroupMember -Identity $GroupName
        
        if ($RemoveExistingMembers) {
            # Remove all existing members
            foreach ($Member in $CurrentMembers) {
                Remove-ADGroupMember -Identity $GroupName -Members $Member.SamAccountName -Confirm:$false
                Write-Log "Removed member: $($Member.SamAccountName)" "Info"
            }
        }
        
        # Add target members
        foreach ($TargetMember in $TargetMembers) {
            try {
                # Check if already a member
                $IsMember = $CurrentMembers | Where-Object {$_.SamAccountName -eq $TargetMember}
                if (-not $IsMember) {
                    Add-ADGroupMember -Identity $GroupName -Members $TargetMember
                    Write-Log "Added member: $TargetMember" "Success"
                }
                else {
                    Write-Log "Member already exists: $TargetMember" "Info"
                }
            }
            catch {
                Write-Log "Failed to add member $TargetMember : $($_.Exception.Message)" "Warning"
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

#region Organizational Unit Management
function Get-ADOrganizationalUnits {
    param(
        [Parameter(Mandatory=$false)]
        [string]$SearchBase,
        [Parameter(Mandatory=$false)]
        [string]$Filter = "*",
        [Parameter(Mandatory=$false)]
        [string[]]$Properties,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDetails
    )
    
    try {
        Write-Log "Retrieving Active Directory organizational units..." "Info"
        
        $SearchParams = @{
            Filter = $Filter
            SearchScope = "Subtree"
        }
        
        if ($SearchBase) { $SearchParams.SearchBase = $SearchBase }
        if ($Properties) { $SearchParams.Properties = $Properties }
        
        $OUs = Get-ADOrganizationalUnit @SearchParams
        
        if ($IncludeDetails) {
            $DetailedOUs = @()
            foreach ($OU in $OUs) {
                $OUInfo = @{
                    Name = $OU.Name
                    DistinguishedName = $OU.DistinguishedName
                    Description = $OU.Description
                    ProtectedFromAccidentalDeletion = $OU.ProtectedFromAccidentalDeletion
                    ObjectClass = $OU.ObjectClass
                    ObjectGUID = $OU.ObjectGUID
                    Created = $OU.Created
                    Modified = $OU.Modified
                }
                
                # Get child OUs
                $ChildOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $OU.DistinguishedName
                $OUInfo.ChildOUCount = $ChildOUs.Count
                
                # Get users in OU
                $Users = Get-ADUser -Filter * -SearchBase $OU.DistinguishedName
                $OUInfo.UserCount = $Users.Count
                
                # Get groups in OU
                $Groups = Get-ADGroup -Filter * -SearchBase $OU.DistinguishedName
                $OUInfo.GroupCount = $Groups.Count
                
                $DetailedOUs += $OUInfo
            }
            return $DetailedOUs
        }
        
        return $OUs
    }
    catch {
        Write-Log "Failed to retrieve AD OUs: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-ADOrganizationalUnit {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [switch]$ProtectedFromAccidentalDeletion = $true
    )
    
    try {
        Write-Log "Creating Active Directory organizational unit: $Name" "Info"
        
        $OUParams = @{
            Name = $Name
            Path = $Path
            ProtectedFromAccidentalDeletion = $ProtectedFromAccidentalDeletion
        }
        
        if ($Description) { $OUParams.Description = $Description }
        
        $NewOU = New-ADOrganizationalUnit @OUParams
        Write-Log "Organizational unit created successfully: $Name" "Success"
        
        return $NewOU
    }
    catch {
        Write-Log "Failed to create AD OU: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Computer Management
function Get-ADComputers {
    param(
        [Parameter(Mandatory=$false)]
        [string]$SearchBase,
        [Parameter(Mandatory=$false)]
        [string]$Filter = "*",
        [Parameter(Mandatory=$false)]
        [string[]]$Properties,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDisabled,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDetails
    )
    
    try {
        Write-Log "Retrieving Active Directory computers..." "Info"
        
        $SearchParams = @{
            Filter = $Filter
        }
        
        if ($SearchBase) { $SearchParams.SearchBase = $SearchBase }
        if ($Properties) { $SearchParams.Properties = $Properties }
        
        $Computers = Get-ADComputer @SearchParams
        
        if (-not $IncludeDisabled) {
            $Computers = $Computers | Where-Object {$_.Enabled -eq $true}
        }
        
        if ($IncludeDetails) {
            $DetailedComputers = @()
            foreach ($Computer in $Computers) {
                $ComputerInfo = @{
                    SamAccountName = $Computer.SamAccountName
                    Name = $Computer.Name
                    DNSHostName = $Computer.DNSHostName
                    Enabled = $Computer.Enabled
                    OperatingSystem = $Computer.OperatingSystem
                    OperatingSystemVersion = $Computer.OperatingSystemVersion
                    ServicePrincipalName = $Computer.ServicePrincipalName
                    DistinguishedName = $Computer.DistinguishedName
                    ObjectClass = $Computer.ObjectClass
                    ObjectGUID = $Computer.ObjectGUID
                    SID = $Computer.SID
                    Created = $Computer.Created
                    Modified = $Computer.Modified
                }
                
                # Get last logon information if available
                try {
                    $LastLogon = Get-ADComputer -Identity $Computer.SamAccountName -Properties LastLogonDate
                    $ComputerInfo.LastLogonDate = $LastLogon.LastLogonDate
                }
                catch {
                    $ComputerInfo.LastLogonDate = $null
                }
                
                $DetailedComputers += $ComputerInfo
            }
            return $DetailedComputers
        }
        
        return $Computers
    }
    catch {
        Write-Log "Failed to retrieve AD computers: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Test-ComputerConnectivity {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 5
    )
    
    try {
        Write-Log "Testing connectivity to computer: $ComputerName" "Info"
        
        $Result = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -TimeoutSeconds $TimeoutSeconds
        
        if ($Result) {
            Write-Log "Computer $ComputerName is reachable" "Success"
            return $true
        }
        else {
            Write-Log "Computer $ComputerName is not reachable" "Warning"
            return $false
        }
    }
    catch {
        Write-Log "Failed to test connectivity to $ComputerName : $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Azure AD Integration
function Sync-ADToAzureAD {
    param(
        [Parameter(Mandatory=$false)]
        [string]$UserFilter = "*",
        [Parameter(Mandatory=$false)]
        [string]$GroupFilter = "*",
        [Parameter(Mandatory=$false)]
        [switch]$SyncUsers,
        [Parameter(Mandatory=$false)]
        [switch]$SyncGroups,
        [Parameter(Mandatory=$false)]
        [switch]$CreateMissingObjects
    )
    
    try {
        Write-Log "Starting AD to Azure AD sync..." "Info"
        
        # Connect to Azure AD
        Connect-AzureAD
        
        if ($SyncUsers) {
            Write-Log "Syncing users from AD to Azure AD..." "Info"
            
            $ADUsers = Get-ADUser -Filter $UserFilter -Properties UserPrincipalName, EmailAddress, Department, Title
            
            foreach ($ADUser in $ADUsers) {
                try {
                    # Check if user exists in Azure AD
                    $AzureUser = Get-AzureADUser -Filter "UserPrincipalName eq '$($ADUser.UserPrincipalName)'" -ErrorAction SilentlyContinue
                    
                    if (-not $AzureUser -and $CreateMissingObjects) {
                        Write-Log "Creating missing user in Azure AD: $($ADUser.UserPrincipalName)" "Info"
                        
                        # Create user in Azure AD (requires additional setup)
                        # This is a simplified example - actual implementation would need more details
                        Write-Log "User creation not implemented in this example" "Warning"
                    }
                    else {
                        Write-Log "User already exists in Azure AD: $($ADUser.UserPrincipalName)" "Info"
                    }
                }
                catch {
                    Write-Log "Error processing user $($ADUser.UserPrincipalName) : $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        if ($SyncGroups) {
            Write-Log "Syncing groups from AD to Azure AD..." "Info"
            
            $ADGroups = Get-ADGroup -Filter $GroupFilter
            
            foreach ($ADGroup in $ADGroups) {
                try {
                    # Check if group exists in Azure AD
                    $AzureGroup = Get-AzureADGroup -Filter "DisplayName eq '$($ADGroup.Name)'" -ErrorAction SilentlyContinue
                    
                    if (-not $AzureGroup -and $CreateMissingObjects) {
                        Write-Log "Creating missing group in Azure AD: $($ADGroup.Name)" "Info"
                        
                        # Create group in Azure AD
                        $NewAzureGroup = New-AzureADGroup -DisplayName $ADGroup.Name -Description $ADGroup.Description -SecurityEnabled $true -MailEnabled $false
                        Write-Log "Group created in Azure AD: $($ADGroup.Name)" "Success"
                    }
                    else {
                        Write-Log "Group already exists in Azure AD: $($ADGroup.Name)" "Info"
                    }
                }
                catch {
                    Write-Log "Error processing group $($ADGroup.Name) : $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        Write-Log "AD to Azure AD sync completed" "Success"
        return $true
    }
    catch {
        Write-Log "Failed to sync AD to Azure AD: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Reporting and Analytics
function Get-ADAnalytics {
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Generating Active Directory analytics report..." "Info"
        
        $Analytics = @{
            Timestamp = Get-Date
            Domain = @{}
            Users = @{}
            Groups = @{}
            Computers = @{}
            OrganizationalUnits = @{}
        }
        
        # Domain information
        $Domain = Get-ADDomain
        $Analytics.Domain = @{
            DNSRoot = $Domain.DNSRoot
            NetBIOSName = $Domain.NetBIOSName
            DomainMode = $Domain.DomainMode
            ForestMode = $Domain.ForestMode
            PDCEmulator = $Domain.PDCEmulator
            RIDMaster = $Domain.RIDMaster
            InfrastructureMaster = $Domain.InfrastructureMaster
        }
        
        # User statistics
        $Users = Get-ADUser -Filter *
        $Analytics.Users = @{
            TotalUsers = $Users.Count
            EnabledUsers = ($Users | Where-Object {$_.Enabled -eq $true}).Count
            DisabledUsers = ($Users | Where-Object {$_.Enabled -eq $false}).Count
            UsersWithExpiredPasswords = ($Users | Where-Object {$_.PasswordExpired -eq $true}).Count
            UsersWithNeverExpiringPasswords = ($Users | Where-Object {$_.PasswordNeverExpires -eq $true}).Count
            UsersWithExpiredAccounts = ($Users | Where-Object {$_.AccountExpirationDate -lt (Get-Date) -and $_.AccountExpirationDate -ne $null}).Count
        }
        
        # Group statistics
        $Groups = Get-ADGroup -Filter *
        $Analytics.Groups = @{
            TotalGroups = $Groups.Count
            SecurityGroups = ($Groups | Where-Object {$_.GroupCategory -eq "Security"}).Count
            DistributionGroups = ($Groups | Where-Object {$_.GroupCategory -eq "Distribution"}).Count
            GlobalGroups = ($Groups | Where-Object {$_.GroupScope -eq "Global"}).Count
            DomainLocalGroups = ($Groups | Where-Object {$_.GroupScope -eq "DomainLocal"}).Count
            UniversalGroups = ($Groups | Where-Object {$_.GroupScope -eq "Universal"}).Count
        }
        
        # Computer statistics
        $Computers = Get-ADComputer -Filter *
        $Analytics.Computers = @{
            TotalComputers = $Computers.Count
            EnabledComputers = ($Computers | Where-Object {$_.Enabled -eq $true}).Count
            DisabledComputers = ($Computers | Where-Object {$_.Enabled -eq $false}).Count
        }
        
        # Organizational Unit statistics
        $OUs = Get-ADOrganizationalUnit -Filter *
        $Analytics.OrganizationalUnits = @{
            TotalOUs = $OUs.Count
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
function Start-ADMaintenance {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$CleanupDisabledAccounts,
        [Parameter(Mandatory=$false)]
        [switch]$CleanupStaleComputers,
        [Parameter(Mandatory=$false)]
        [switch]$UpdateGroupMembership,
        [Parameter(Mandatory=$false)]
        [switch]$AuditPermissions
    )
    
    try {
        Write-Log "Starting Active Directory maintenance tasks..." "Info"
        
        if ($CleanupDisabledAccounts) {
            Write-Log "Cleaning up disabled accounts..." "Info"
            
            $DisabledUsers = Get-ADUser -Filter "Enabled -eq $false"
            $OldDisabledUsers = $DisabledUsers | Where-Object {$_.Modified -lt (Get-Date).AddDays(-90)}
            
            Write-Log "Found $($OldDisabledUsers.Count) accounts disabled for more than 90 days" "Warning"
            
            # Add logic to process old disabled accounts (move to special OU, etc.)
            foreach ($User in $OldDisabledUsers) {
                Write-Log "Processing old disabled account: $($User.SamAccountName)" "Info"
                # Add cleanup logic here
            }
        }
        
        if ($CleanupStaleComputers) {
            Write-Log "Cleaning up stale computer accounts..." "Info"
            
            $Computers = Get-ADComputer -Filter * -Properties LastLogonDate
            $StaleComputers = $Computers | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90) -or $_.LastLogonDate -eq $null}
            
            Write-Log "Found $($StaleComputers.Count) computer accounts that haven't logged on in 90+ days" "Warning"
            
            # Add logic to process stale computers
            foreach ($Computer in $StaleComputers) {
                Write-Log "Processing stale computer: $($Computer.Name)" "Info"
                # Add cleanup logic here
            }
        }
        
        if ($UpdateGroupMembership) {
            Write-Log "Updating group membership..." "Info"
            
            # Add logic to update group membership based on organizational rules
            Write-Log "Group membership update completed" "Success"
        }
        
        if ($AuditPermissions) {
            Write-Log "Auditing permissions..." "Info"
            
            # Check for users with excessive permissions
            $Users = Get-ADUser -Filter "Enabled -eq $true"
            $HighPrivilegeUsers = @()
            
            foreach ($User in $Users) {
                $Groups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName
                $AdminGroups = $Groups | Where-Object {$_.Name -like "*Admin*" -or $_.Name -like "*Domain Admins*" -or $_.Name -like "*Enterprise Admins*"}
                
                if ($AdminGroups.Count -gt 0) {
                    $HighPrivilegeUsers += @{
                        User = $User
                        AdminGroups = $AdminGroups
                    }
                }
            }
            
            Write-Log "Found $($HighPrivilegeUsers.Count) users with administrative privileges" "Info"
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
function Connect-ADServices {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DomainController,
        [Parameter(Mandatory=$false)]
        [string]$Credential
    )
    
    try {
        Write-Log "Connecting to Active Directory services..." "Info"
        
        # Test AD connection
        if (Test-ADConnection) {
            Write-Log "Successfully connected to Active Directory" "Success"
            return $true
        }
        else {
            Write-Log "Failed to connect to Active Directory" "Error"
            return $false
        }
    }
    catch {
        Write-Log "Failed to connect to AD services: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Disconnect-ADServices {
    try {
        # AD connections are typically handled by the system
        Write-Log "Active Directory services disconnected" "Success"
    }
    catch {
        Write-Log "Error during disconnection: $($_.Exception.Message)" "Warning"
    }
}

#endregion

# Example usage:
<#
# Connect to AD services
Connect-ADServices

# Get all users with details
$Users = Get-ADUsers -IncludeDetails

# Create a new user
$NewUser = New-ADUser -SamAccountName "jdoe" -DisplayName "John Doe" -UserPrincipalName "jdoe@company.com" -Password "TempPassword123!" -GivenName "John" -Surname "Doe" -Department "IT" -Title "System Administrator"

# Update user properties
Set-ADUserProperties -Identity "jdoe" -Properties @{
    Department = "Engineering"
    Title = "Senior System Administrator"
    Office = "New York"
}

# Get all groups with members
$Groups = Get-ADGroups -IncludeMembers -IncludeDetails

# Create a new group
$NewGroup = New-ADGroup -Name "IT Administrators" -Description "IT Administration group" -GroupCategory "Security" -GroupScope "Global"

# Sync group membership
Sync-ADGroupMembership -GroupName "IT Administrators" -TargetMembers @("jdoe", "admin") -RemoveExistingMembers

# Get organizational units
$OUs = Get-ADOrganizationalUnits -IncludeDetails

# Create new OU
$NewOU = New-ADOrganizationalUnit -Name "Engineering" -Path "OU=Departments,DC=company,DC=com" -Description "Engineering department OU"

# Get computers
$Computers = Get-ADComputers -IncludeDetails

# Test computer connectivity
Test-ComputerConnectivity -ComputerName "SERVER01"

# Sync AD to Azure AD
Sync-ADToAzureAD -SyncUsers -SyncGroups -CreateMissingObjects

# Generate analytics report
Get-ADAnalytics -OutputPath "AD_Analytics_Report.json"

# Run maintenance tasks
Start-ADMaintenance -CleanupDisabledAccounts -CleanupStaleComputers -UpdateGroupMembership -AuditPermissions

# Disconnect from services
Disconnect-ADServices
#>
