# Windows Server & Active Directory

## Integration with On-Premises AD

### Azure AD Connect Setup
```powershell
# Install Azure AD Connect prerequisites
Install-WindowsFeature -Name AD-Domain-Services, DNS, GPMC

# Configure hybrid identity
Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Initial

# Sync on-premises groups to Azure AD
Get-ADGroup -Filter * | ForEach-Object {
    $AzureGroup = Get-AzureADGroup -Filter "DisplayName eq '$($_.Name)'"
    if (-not $AzureGroup) {
        New-AzureADGroup -DisplayName $_.Name -SecurityEnabled $true -MailEnabled $false
    }
}
```

## Advanced AD Management

### User Management
```powershell
# Create AD user
function New-ADUser {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SamAccountName,
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$true)]
        [string]$Password
    )
    
    try {
        $UserParams = @{
            SamAccountName = $SamAccountName
            DisplayName = $DisplayName
            UserPrincipalName = $UserPrincipalName
            AccountPassword = (ConvertTo-SecureString $Password -AsPlainText -Force)
            Enabled = $true
            ChangePasswordAtLogon = $true
        }
        
        $NewUser = New-ADUser @UserParams
        Write-Host "User created: $SamAccountName" -ForegroundColor Green
        return $NewUser
    }
    catch {
        Write-Error "Failed to create user: $($_.Exception.Message)"
    }
}

# Bulk user creation
function New-BulkADUsers {
    param([string]$CSVPath)
    
    $Users = Import-Csv -Path $CSVPath
    foreach ($User in $Users) {
        New-ADUser -SamAccountName $User.SamAccountName `
                  -DisplayName $User.DisplayName `
                  -UserPrincipalName $User.UserPrincipalName `
                  -Password $User.Password
    }
}
```

### Group Management
```powershell
# Create AD group
function New-ADGroup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Security", "Distribution")]
        [string]$GroupCategory = "Security"
    )
    
    try {
        $GroupParams = @{
            Name = $Name
            GroupCategory = $GroupCategory
            GroupScope = "Global"
        }
        
        if ($Description) { $GroupParams.Description = $Description }
        
        $NewGroup = New-ADGroup @GroupParams
        Write-Host "Group created: $Name" -ForegroundColor Green
        return $NewGroup
    }
    catch {
        Write-Error "Failed to create group: $($_.Exception.Message)"
    }
}

# Sync group membership
function Sync-ADGroupMembership {
    param(
        [string]$GroupName,
        [string[]]$TargetMembers
    )
    
    $Group = Get-ADGroup -Identity $GroupName
    $CurrentMembers = Get-ADGroupMember -Identity $GroupName
    
    # Remove existing members
    foreach ($Member in $CurrentMembers) {
        Remove-ADGroupMember -Identity $GroupName -Members $Member.SamAccountName -Confirm:$false
    }
    
    # Add target members
    foreach ($Member in $TargetMembers) {
        Add-ADGroupMember -Identity $GroupName -Members $Member
    }
}
```

### Organizational Unit Management
```powershell
# Create OU structure
function New-ADOUStructure {
    $OUs = @(
        @{Name="Departments"; Path="DC=company,DC=com"},
        @{Name="IT"; Path="OU=Departments,DC=company,DC=com"},
        @{Name="HR"; Path="OU=Departments,DC=company,DC=com"},
        @{Name="Finance"; Path="OU=Departments,DC=company,DC=com"}
    )
    
    foreach ($OU in $OUs) {
        try {
            New-ADOrganizationalUnit -Name $OU.Name -Path $OU.Path
            Write-Host "Created OU: $($OU.Name)" -ForegroundColor Green
        }
        catch {
            Write-Warning "OU may already exist: $($OU.Name)"
        }
    }
}

# Move users to appropriate OUs
function Move-UsersToOUs {
    $Users = Get-ADUser -Filter * -Properties Department
    
    foreach ($User in $Users) {
        if ($User.Department) {
            $TargetOU = "OU=$($User.Department),OU=Departments,DC=company,DC=com"
            try {
                Move-ADObject -Identity $User.DistinguishedName -TargetPath $TargetOU
                Write-Host "Moved $($User.SamAccountName) to $TargetOU" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to move $($User.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
}
```

### Computer Management
```powershell
# Get computer information
function Get-ADComputerInfo {
    param([string]$ComputerName)
    
    $Computer = Get-ADComputer -Identity $ComputerName -Properties *
    
    $ComputerInfo = @{
        Name = $Computer.Name
        DNSHostName = $Computer.DNSHostName
        OperatingSystem = $Computer.OperatingSystem
        LastLogonDate = $Computer.LastLogonDate
        Enabled = $Computer.Enabled
        DistinguishedName = $Computer.DistinguishedName
    }
    
    return $ComputerInfo
}

# Clean up stale computer accounts
function Remove-StaleComputers {
    param([int]$DaysInactive = 90)
    
    $CutoffDate = (Get-Date).AddDays(-$DaysInactive)
    $StaleComputers = Get-ADComputer -Filter {LastLogonDate -lt $CutoffDate} -Properties LastLogonDate
    
    foreach ($Computer in $StaleComputers) {
        Write-Host "Removing stale computer: $($Computer.Name)" -ForegroundColor Yellow
        Remove-ADComputer -Identity $Computer.Name -Confirm:$false
    }
}
```

## Hybrid Identity Synchronization

### Azure AD Connect Management
```powershell
# Check sync status
function Get-SyncStatus {
    $SyncStatus = Get-ADSyncConnectorRunStatus
    
    $StatusReport = @{
        LastSyncTime = $SyncStatus.LastSuccessfulRun
        LastSyncResult = $SyncStatus.LastSuccessfulRunResult
        ConnectorStatus = $SyncStatus.ConnectorStatus
    }
    
    return $StatusReport
}

# Force full synchronization
function Start-FullSync {
    Write-Host "Starting full synchronization..." -ForegroundColor Yellow
    Start-ADSyncSyncCycle -PolicyType Initial
    
    # Wait for sync to complete
    do {
        Start-Sleep -Seconds 30
        $Status = Get-ADSyncConnectorRunStatus
        Write-Host "Sync in progress..." -ForegroundColor Yellow
    } while ($Status.ConnectorStatus -eq "Running")
    
    Write-Host "Synchronization completed" -ForegroundColor Green
}

# Sync specific OUs
function Sync-SpecificOUs {
    param([string[]]$OUDistinguishedNames)
    
    foreach ($OU in $OUDistinguishedNames) {
        Write-Host "Syncing OU: $OU" -ForegroundColor Yellow
        
        # Get users in OU
        $Users = Get-ADUser -Filter * -SearchBase $OU
        
        foreach ($User in $Users) {
            # Force sync for specific user
            $UserGUID = (Get-ADUser -Identity $User.SamAccountName).ObjectGUID
            Start-ADSyncSyncCycle -PolicyType Delta -CustomADConnectorName "company.onmicrosoft.com - AAD" -CustomConnectorParameter @{ObjectId=$UserGUID}
        }
    }
}
```

### Group Synchronization
```powershell
# Sync AD groups to Azure AD
function Sync-ADGroupsToAzure {
    $ADGroups = Get-ADGroup -Filter {GroupScope -eq "Global"} -Properties Description
    
    foreach ($Group in $ADGroups) {
        $AzureGroup = Get-AzureADGroup -Filter "DisplayName eq '$($Group.Name)'"
        
        if (-not $AzureGroup) {
            # Create group in Azure AD
            New-AzureADGroup -DisplayName $Group.Name `
                            -Description $Group.Description `
                            -SecurityEnabled $true `
                            -MailEnabled $false
            Write-Host "Created Azure AD group: $($Group.Name)" -ForegroundColor Green
        }
        else {
            Write-Host "Group already exists: $($Group.Name)" -ForegroundColor Yellow
        }
    }
}

# Sync group membership
function Sync-GroupMembership {
    $ADGroups = Get-ADGroup -Filter {GroupScope -eq "Global"}
    
    foreach ($ADGroup in $ADGroups) {
        $AzureGroup = Get-AzureADGroup -Filter "DisplayName eq '$($ADGroup.Name)'"
        
        if ($AzureGroup) {
            # Get AD group members
            $ADMembers = Get-ADGroupMember -Identity $ADGroup.SamAccountName
            
            # Get Azure AD group members
            $AzureMembers = Get-AzureADGroupMember -ObjectId $AzureGroup.ObjectId
            
            # Sync membership
            foreach ($ADMember in $ADMembers) {
                $AzureUser = Get-AzureADUser -Filter "UserPrincipalName eq '$($ADMember.UserPrincipalName)'"
                
                if ($AzureUser -and $AzureMembers.ObjectId -notcontains $AzureUser.ObjectId) {
                    Add-AzureADGroupMember -ObjectId $AzureGroup.ObjectId -RefObjectId $AzureUser.ObjectId
                    Write-Host "Added $($ADMember.UserPrincipalName) to Azure group $($ADGroup.Name)" -ForegroundColor Green
                }
            }
        }
    }
}
```

## Advanced AD Administration

### Password Management
```powershell
# Reset user password
function Reset-ADUserPassword {
    param(
        [string]$SamAccountName,
        [string]$NewPassword
    )
    
    try {
        $SecurePassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
        Set-ADAccountPassword -Identity $SamAccountName -NewPassword $SecurePassword
        Set-ADUser -Identity $SamAccountName -ChangePasswordAtLogon $true
        
        Write-Host "Password reset for: $SamAccountName" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to reset password: $($_.Exception.Message)"
    }
}

# Check password expiration
function Get-PasswordExpiration {
    $Users = Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordLastSet, PasswordExpired
    
    $ExpiringSoon = $Users | Where-Object {
        $_.PasswordLastSet -lt (Get-Date).AddDays(-80) -and $_.PasswordExpired -eq $false
    }
    
    return $ExpiringSoon | Select-Object SamAccountName, DisplayName, PasswordLastSet
}
```

### Active Directory Health Monitoring
```powershell
function Get-ADHealthStatus {
    $HealthReport = @{
        Timestamp = Get-Date
        DomainControllers = @()
        ReplicationStatus = @{}
        Services = @{}
        Issues = @()
    }
    
    # Check domain controllers
    $DomainControllers = Get-ADDomainController -Filter *
    foreach ($DC in $DomainControllers) {
        $DCInfo = @{
            Name = $DC.Name
            Site = $DC.Site
            IsGlobalCatalog = $DC.IsGlobalCatalog
            IsReadOnly = $DC.IsReadOnly
            Status = "Healthy"
        }
        
        # Test connectivity
        if (Test-Connection -ComputerName $DC.Name -Count 1 -Quiet) {
            $DCInfo.Status = "Healthy"
        } else {
            $DCInfo.Status = "Unreachable"
            $HealthReport.Issues += "Domain Controller $($DC.Name) is unreachable"
        }
        
        $HealthReport.DomainControllers += $DCInfo
    }
    
    # Check replication status
    try {
        $ReplicationStatus = Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME
        $HealthReport.ReplicationStatus = @{
            Status = "Healthy"
            LastReplication = $ReplicationStatus.LastReplicationSuccess
        }
    }
    catch {
        $HealthReport.ReplicationStatus = @{
            Status = "Error"
            Error = $_.Exception.Message
        }
        $HealthReport.Issues += "Replication check failed: $($_.Exception.Message)"
    }
    
    return $HealthReport
}
```

## Best Practices

### AD Management
1. **Regular Backups**: Backup AD regularly
2. **Monitoring**: Monitor AD health and replication
3. **Documentation**: Document AD structure and changes
4. **Testing**: Test changes in development environment

### Security
1. **Least Privilege**: Use least privilege access
2. **Regular Audits**: Audit AD permissions regularly
3. **Password Policies**: Implement strong password policies
4. **Account Lockout**: Configure appropriate lockout policies

### Hybrid Identity
1. **Sync Monitoring**: Monitor Azure AD Connect sync
2. **Conflict Resolution**: Handle sync conflicts properly
3. **Testing**: Test sync changes thoroughly
4. **Documentation**: Document sync configuration

---

*This guide covers Windows Server and Active Directory management. For integration with M365 services, refer to the Azure AD Connect and hybrid identity documentation.*
