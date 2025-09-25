# Getting Started with Microsoft 365

## What is Microsoft 365?

Microsoft 365 is a cloud-based productivity suite that combines Office 365 applications with Windows 10/11 and enterprise mobility and security features.

## Core Components

### Identity and Access Management
- **Entra ID (formerly Azure AD)**: Cloud-based identity and access management service
- **Azure AD B2B/B2C**: External user collaboration and customer identity management
- **Multi-Factor Authentication (MFA)**: Enhanced security for user accounts

### Productivity and Collaboration
- **Office 365 Apps**: Word, Excel, PowerPoint, Outlook, Teams, SharePoint
- **Microsoft Teams**: Communication and collaboration platform
- **SharePoint Online**: Document management and intranet
- **OneDrive for Business**: Personal cloud storage

### Device and Application Management
- **Microsoft Intune**: Mobile device and application management (MDM/MAM)
- **Windows Autopilot**: Automated device deployment
- **Microsoft Defender**: Endpoint security and threat protection

### Data Governance and Compliance
- **Microsoft Purview**: Unified data governance and compliance
- **Data Loss Prevention (DLP)**: Prevent sensitive data from leaving your organization
- **Information Protection**: Classify and protect sensitive information
- **Compliance Manager**: Assess compliance posture

### Cloud Platform Services
- **Azure**: Cloud computing platform and services
- **Azure Virtual Machines**: Cloud-based virtual machines
- **Azure Active Directory Domain Services**: Managed domain services
- **Azure Backup**: Backup and recovery services

## Getting Started Checklist

### 1. Set Up Your M365 Tenant
- [ ] Purchase appropriate M365 licenses
- [ ] Configure custom domain
- [ ] Set up DNS records
- [ ] Verify domain ownership

### 2. Configure Basic Security Settings
- [ ] Enable security defaults
- [ ] Configure conditional access policies
- [ ] Set up multi-factor authentication
- [ ] Configure password policies

### 3. Understand Licensing Models
- [ ] Review available license types
- [ ] Understand feature differences between plans
- [ ] Plan license allocation strategy
- [ ] Set up license management processes

### 4. Set Up Administrative Roles
- [ ] Create administrative accounts
- [ ] Assign appropriate roles
- [ ] Configure role-based access control (RBAC)
- [ ] Set up administrative units

### 5. Configure Basic Policies
- [ ] Create user provisioning policies
- [ ] Set up device compliance policies
- [ ] Configure data loss prevention rules
- [ ] Establish retention policies

## Common M365 Admin Roles

### Global Administrator
- Full access to all M365 features
- Can manage all aspects of the tenant
- Should be limited to essential personnel

### User Administrator
- Manage user accounts and licenses
- Reset passwords
- Manage group memberships
- Cannot modify administrative roles

### Security Administrator
- Manage security policies and settings
- Monitor security events
- Configure conditional access
- Manage security compliance

### Compliance Administrator
- Manage compliance policies
- Configure data loss prevention
- Manage retention policies
- Access compliance reports

### Intune Administrator
- Manage mobile devices and applications
- Configure device compliance policies
- Deploy and manage applications
- Monitor device compliance

### SharePoint Administrator
- Manage SharePoint Online settings
- Configure site collections
- Manage user permissions
- Monitor SharePoint usage

## Essential PowerShell Modules

### Core Modules
```powershell
# Microsoft Graph (Modern PowerShell)
Install-Module -Name Microsoft.Graph -Force

# Azure AD (Legacy but still useful)
Install-Module -Name AzureAD -Force

# Exchange Online
Install-Module -Name ExchangeOnlineManagement -Force

# Teams
Install-Module -Name MicrosoftTeams -Force
```

### Additional Modules
```powershell
# SharePoint Online
Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Force

# Security & Compliance
Install-Module -Name SecurityComplianceCenter -Force

# Azure (for cloud services)
Install-Module -Name Az -Force
```

## Basic Connection Commands

### Connect to Microsoft Graph
```powershell
# Connect with required scopes
Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All"

# Connect to specific tenant
Connect-MgGraph -TenantId "your-tenant-id"
```

### Connect to Azure AD (Legacy)
```powershell
# Connect to Azure AD
Connect-AzureAD

# Connect with credentials
Connect-AzureAD -Credential $Credential
```

### Connect to Exchange Online
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Connect with specific user
Connect-ExchangeOnline -UserPrincipalName "admin@company.com"
```

### Connect to Teams
```powershell
# Connect to Microsoft Teams
Connect-MicrosoftTeams

# Connect with credentials
Connect-MicrosoftTeams -Credential $Credential
```

## Basic Administrative Tasks

### User Management
```powershell
# Get all users
Get-MgUser -All

# Create a new user
$PasswordProfile = @{
    Password = "TempPassword123!"
    ForceChangePasswordNextLogin = $true
}
New-MgUser -DisplayName "John Doe" -UserPrincipalName "john.doe@company.com" -PasswordProfile $PasswordProfile -AccountEnabled

# Get user by UPN
Get-MgUser -UserId "john.doe@company.com"
```

### Group Management
```powershell
# Get all groups
Get-MgGroup -All

# Create a security group
New-MgGroup -DisplayName "IT Department" -SecurityEnabled -MailEnabled:$false

# Add user to group
New-MgGroupMember -GroupId "group-id" -DirectoryObjectId "user-id"
```

### License Management
```powershell
# Get available licenses
Get-MgSubscribedSku

# Assign license to user
$License = Get-MgSubscribedSku | Where-Object {$_.SkuPartNumber -eq "ENTERPRISEPACK"}
Set-MgUserLicense -UserId "user-id" -AddLicenses @{SkuId = $License.SkuId}
```

## Security Best Practices

### 1. Enable Security Defaults
- Provides baseline security settings
- Enables MFA for all users
- Blocks legacy authentication
- Requires security admin to register for MFA

### 2. Configure Conditional Access
- Control access based on conditions
- Require MFA from untrusted locations
- Block access from risky sign-ins
- Require compliant devices

### 3. Regular Security Reviews
- Review administrative roles quarterly
- Audit user permissions regularly
- Monitor sign-in logs for anomalies
- Review and update security policies

### 4. Data Protection
- Enable data loss prevention
- Configure information protection labels
- Set up retention policies
- Monitor data sharing and access

## Common Troubleshooting

### Authentication Issues
- Verify user credentials
- Check MFA status
- Review conditional access policies
- Validate license assignments

### Permission Issues
- Verify role assignments
- Check group memberships
- Review administrative units
- Validate service principal permissions

### Connectivity Issues
- Test network connectivity
- Verify firewall settings
- Check proxy configuration
- Validate DNS resolution

## Next Steps

1. **Explore Service-Specific Documentation**
   - Entra ID fundamentals
   - Intune device management
   - Purview data governance
   - Azure integration

2. **Practice with PowerShell**
   - Start with basic user management
   - Progress to advanced automation
   - Learn error handling and logging
   - Implement security best practices

3. **Set Up Monitoring**
   - Configure audit logging
   - Set up security monitoring
   - Implement compliance reporting
   - Create alerting and notifications

---

*This guide provides the foundation for M365 administration. Continue with service-specific documentation for detailed implementation guidance.*
