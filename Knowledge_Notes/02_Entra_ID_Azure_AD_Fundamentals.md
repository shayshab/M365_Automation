# Entra ID (Azure AD) Fundamentals

## Understanding Entra ID

Entra ID is Microsoft's cloud-based identity and access management service that provides secure authentication and authorization for users and applications.

## Key Concepts

### Core Components
- **Tenant**: Your organization's dedicated instance of Azure AD
- **Users**: Individual accounts in your organization
- **Groups**: Collections of users for easier management
- **Applications**: Apps that can integrate with Azure AD
- **Service Principals**: Security principals used by applications
- **Conditional Access**: Policies that control access based on conditions

### Identity Types
- **Cloud Identities**: Created and managed in Azure AD
- **Directory Synchronized**: Synced from on-premises Active Directory
- **Guest Users**: External users invited to collaborate
- **Service Accounts**: Non-human accounts for applications

### Authentication Methods
- **Password**: Traditional username/password authentication
- **Multi-Factor Authentication (MFA)**: Additional verification methods
- **Certificate-based**: Authentication using certificates
- **FIDO2/Windows Hello**: Modern authentication methods

## Basic Administration Tasks

### User Management

#### Create a New User
```powershell
# Connect to Azure AD
Connect-AzureAD

# Create password profile
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = "TempPassword123!"
$PasswordProfile.ForceChangePasswordNextLogin = $true

# Create user
New-AzureADUser -DisplayName "John Doe" `
                -UserPrincipalName "john.doe@company.com" `
                -PasswordProfile $PasswordProfile `
                -AccountEnabled $true `
                -JobTitle "System Administrator" `
                -Department "IT"
```

#### Get User Information
```powershell
# Get all users
Get-AzureADUser

# Get user by UPN
Get-AzureADUser -Filter "UserPrincipalName eq 'john.doe@company.com'"

# Get user with specific properties
Get-AzureADUser -Filter "UserPrincipalName eq 'john.doe@company.com'" `
                -Properties DisplayName, JobTitle, Department, LastSignInDateTime
```

#### Update User Properties
```powershell
# Update user properties
Set-AzureADUser -ObjectId "user@company.com" `
                -JobTitle "Senior System Administrator" `
                -Department "Engineering" `
                -Office "New York"
```

### Group Management

#### Create Groups
```powershell
# Create security group
New-AzureADGroup -DisplayName "IT Department" `
                 -SecurityEnabled $true `
                 -MailEnabled $false `
                 -Description "IT department security group"

# Create mail-enabled security group
New-AzureADGroup -DisplayName "IT Team" `
                 -SecurityEnabled $true `
                 -MailEnabled $true `
                 -MailNickname "ITTeam"

# Create distribution group
New-AzureADGroup -DisplayName "All Employees" `
                 -SecurityEnabled $false `
                 -MailEnabled $true `
                 -MailNickname "AllEmployees"
```

#### Manage Group Membership
```powershell
# Add user to group
Add-AzureADGroupMember -ObjectId "group-object-id" -RefObjectId "user-object-id"

# Remove user from group
Remove-AzureADGroupMember -ObjectId "group-object-id" -MemberId "user-object-id"

# Get group members
Get-AzureADGroupMember -ObjectId "group-object-id"

# Get group owners
Get-AzureADGroupOwner -ObjectId "group-object-id"
```

### Application Management

#### Register Applications
```powershell
# Create web application
New-AzureADApplication -DisplayName "My Web App" `
                       -HomePage "https://myapp.company.com" `
                       -ReplyUrls @("https://myapp.company.com/auth") `
                       -IdentifierUris @("https://company.com/myapp")

# Create native application
New-AzureADApplication -DisplayName "My Mobile App" `
                       -PublicClient $true
```

#### Configure Application Permissions
```powershell
# Get application
$App = Get-AzureADApplication -Filter "DisplayName eq 'My Web App'"

# Add required resource access
$ResourceAccess = @{
    ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
    ResourceAccess = @(
        @{
            Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"  # User.Read
            Type = "Scope"
        }
    )
}

Set-AzureADApplication -ObjectId $App.ObjectId -RequiredResourceAccess @($ResourceAccess)
```

## Advanced User Provisioning

### Bulk User Creation from CSV
```powershell
# Import users from CSV
$Users = Import-Csv -Path "C:\Users.csv"

foreach ($User in $Users) {
    try {
        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        $PasswordProfile.Password = $User.TemporaryPassword
        $PasswordProfile.ForceChangePasswordNextLogin = $true
        
        New-AzureADUser -DisplayName $User.DisplayName `
                       -UserPrincipalName $User.UserPrincipalName `
                       -PasswordProfile $PasswordProfile `
                       -AccountEnabled $true `
                       -JobTitle $User.JobTitle `
                       -Department $User.Department `
                       -GivenName $User.GivenName `
                       -Surname $User.Surname
        
        Write-Host "Created user: $($User.UserPrincipalName)" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to create user $($User.UserPrincipalName): $($_.Exception.Message)" -ForegroundColor Red
    }
}
```

### Dynamic Group Management
```powershell
# Create dynamic group
$DynamicGroup = @{
    DisplayName = "All Sales Users"
    Description = "Dynamic group for all sales department users"
    MailEnabled = $false
    SecurityEnabled = $true
    GroupTypes = @("DynamicMembership")
    MembershipRule = "user.department -eq \"Sales\""
    MembershipRuleProcessingState = "On"
}

New-AzureADMSGroup @DynamicGroup
```

### User Lifecycle Automation
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
        # Create user
        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        $PasswordProfile.Password = [System.Web.Security.Membership]::GeneratePassword(12, 4)
        
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
        
        return $NewUser
    }
    catch {
        Write-Error "Failed to create user: $($_.Exception.Message)"
    }
}
```

## License Management

### License Assignment
```powershell
# Get available licenses
Get-AzureADSubscribedSku

# Assign license to user
$User = Get-AzureADUser -Filter "UserPrincipalName eq 'john.doe@company.com'"
$License = Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq "ENTERPRISEPACK"}

Set-AzureADUserLicense -ObjectId $User.ObjectId -AssignedLicenses @{SkuId = $License.SkuId}

# Remove license from user
Set-AzureADUserLicense -ObjectId $User.ObjectId -AssignedLicenses @{} -RemoveLicenses @{SkuId = $License.SkuId}
```

### Bulk License Management
```powershell
# Assign licenses to multiple users
$Users = @("user1@company.com", "user2@company.com", "user3@company.com")
$License = Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq "ENTERPRISEPACK"}

foreach ($UserPrincipalName in $Users) {
    $User = Get-AzureADUser -Filter "UserPrincipalName eq '$UserPrincipalName'"
    if ($User) {
        Set-AzureADUserLicense -ObjectId $User.ObjectId -AssignedLicenses @{SkuId = $License.SkuId}
        Write-Host "Assigned license to $UserPrincipalName" -ForegroundColor Green
    }
}
```

## Conditional Access Policies

### Basic Conditional Access Policy
```powershell
# Note: Conditional Access policies require Microsoft Graph PowerShell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$CAPolicy = @{
    displayName = "Require MFA for Admin Users"
    state = "Enabled"
    conditions = @{
        applications = @{
            includeApplications = @("All")
        }
        users = @{
            includeUsers = @("All")
            includeRoles = @("62e90394-69f5-4237-9190-012177145e10")  # Global Administrator
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $CAPolicy
```

### Advanced Conditional Access Scenarios
```powershell
# Require MFA from untrusted locations
$CAPolicy = @{
    displayName = "Require MFA from Untrusted Locations"
    state = "Enabled"
    conditions = @{
        applications = @{
            includeApplications = @("All")
        }
        users = @{
            includeUsers = @("All")
        }
        locations = @{
            includeLocations = @("All")
            excludeLocations = @("TrustedLocations")
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}
```

## Security and Monitoring

### Risk Events and Sign-ins
```powershell
# Get risky users
Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All"

$RiskyUsers = Get-MgIdentityRiskEvent -Top 100
$HighRiskUsers = $RiskyUsers | Where-Object {$_.RiskLevel -eq "High"}

# Get sign-in logs
$SignIns = Get-MgAuditLogSignIn -Top 100
$FailedSignIns = $SignIns | Where-Object {$_.Status.ErrorCode -ne 0}
```

### Security Reports
```powershell
function Get-SecurityReport {
    $Report = @{
        Timestamp = Get-Date
        RiskyUsers = @()
        FailedSignIns = @()
        MFAUsage = @{}
    }
    
    # Get risky users
    $RiskyUsers = Get-MgIdentityRiskEvent -Top 100
    $Report.RiskyUsers = $RiskyUsers | Select-Object UserPrincipalName, RiskLevel, RiskState
    
    # Get failed sign-ins
    $SignIns = Get-MgAuditLogSignIn -Top 1000
    $Report.FailedSignIns = $SignIns | Where-Object {$_.Status.ErrorCode -ne 0} | Select-Object UserPrincipalName, CreatedDateTime, Status
    
    # Calculate MFA usage
    $MFASignIns = $SignIns | Where-Object {$_.AuthenticationMethodsUsed -contains "mfa"}
    $TotalSignIns = $SignIns.Count
    $Report.MFAUsage = @{
        TotalSignIns = $TotalSignIns
        MFASignIns = $MFASignIns.Count
        MFAUsagePercentage = [math]::Round(($MFASignIns.Count / $TotalSignIns) * 100, 2)
    }
    
    return $Report
}
```

## Hybrid Identity Integration

### Azure AD Connect
```powershell
# Check Azure AD Connect status
Get-ADSyncConnectorRunStatus

# Force synchronization
Start-ADSyncSyncCycle -PolicyType Initial

# Check sync errors
Get-ADSyncRunProfileResult
```

### On-premises Integration
```powershell
# Sync on-premises groups to Azure AD
Get-ADGroup -Filter * | ForEach-Object {
    $AzureGroup = Get-AzureADGroup -Filter "DisplayName eq '$($_.Name)'"
    if (-not $AzureGroup) {
        New-AzureADGroup -DisplayName $_.Name -SecurityEnabled $true -MailEnabled $false
        Write-Host "Created Azure AD group: $($_.Name)" -ForegroundColor Green
    }
}
```

## Best Practices

### User Management
1. Use consistent naming conventions
2. Implement proper group-based permissions
3. Regular access reviews
4. Automated provisioning where possible

### Security
1. Enable MFA for all users
2. Use conditional access policies
3. Regular security monitoring
4. Implement least privilege access

### Monitoring
1. Enable audit logging
2. Regular security reports
3. Monitor sign-in patterns
4. Track license usage

### Automation
1. Use PowerShell for bulk operations
2. Implement error handling
3. Log all administrative actions
4. Test scripts in development environment

---

*This guide covers the fundamentals of Entra ID administration. For advanced scenarios and integration with other M365 services, refer to the service-specific documentation.*
