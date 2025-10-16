# Microsoft 365 Administration Scripts

This repository contains comprehensive PowerShell scripts for Microsoft 365 administration, covering all major M365 services from beginner to advanced levels.

## 📁 Repository Structure

```
M365_scripts/
├── README.md                        # This file
├── Knowledge_Notes/                 # Comprehensive knowledge documentation
│   ├── 01_Getting_Started_M365.md           # Getting started with M365
│   ├── 02_Entra_ID_Azure_AD_Fundamentals.md # Entra ID (Azure AD) fundamentals
│   ├── 03_Microsoft_Intune_Management.md    # Microsoft Intune management
│   ├── 04_Microsoft_Purview.md              # Microsoft Purview data governance
│   ├── 05_Azure_Integration.md              # Azure integration
│   ├── 06_PowerShell_Automation.md          # PowerShell automation
│   ├── 07_Windows_Server_Active_Directory.md # Windows Server & Active Directory
│   └── 08_Advanced_Topics.md                # Advanced topics and scenarios
└── Scripts/                         # PowerShell automation scripts
    ├── User_Management_Scripts.ps1          # Azure AD user lifecycle management
    ├── Intune_Management_Scripts.ps1        # Microsoft Intune device management
    ├── Azure_AD_Management_Scripts.ps1      # Azure AD administration
    ├── Purview_Management_Scripts.ps1       # Microsoft Purview data governance
    └── Windows_Server_AD_Scripts.ps1        # Windows Server & Active Directory
```

## 🚀 Quick Start

### Prerequisites

Before running any scripts, install the required PowerShell modules:

```powershell
# Core modules
Install-Module -Name Microsoft.Graph -Force
Install-Module -Name AzureAD -Force
Install-Module -Name ExchangeOnlineManagement -Force

# Additional modules for specific scenarios
Install-Module -Name ActiveDirectory -Force  # For on-premises AD
Install-Module -Name MSOnline -Force         # Legacy M365 admin
```

### Basic Usage

1. **Connect to M365 services:**
```powershell
# Import the script
. .\Scripts\User_Management_Scripts.ps1

# Connect to services
Connect-M365Services
```

2. **Create a new user:**
```powershell
$NewUser = New-M365User -DisplayName "John Doe" -UserPrincipalName "john.doe@company.com" -Department "IT" -JobTitle "System Administrator"
```

3. **Generate reports:**
```powershell
Get-UserReport -Department "IT" -OutputPath "IT_Users_Report.csv"
```

## 📚 Knowledge Documentation

The `Knowledge_Notes/` directory contains comprehensive documentation organized by topic:

### Getting Started
- **[01_Getting_Started_M365.md](Knowledge_Notes/01_Getting_Started_M365.md)**: Basic M365 concepts, setup, and essential administrative tasks

### Core Services
- **[02_Entra_ID_Azure_AD_Fundamentals.md](Knowledge_Notes/02_Entra_ID_Azure_AD_Fundamentals.md)**: Identity and access management with Entra ID
- **[03_Microsoft_Intune_Management.md](Knowledge_Notes/03_Microsoft_Intune_Management.md)**: Device and application management
- **[04_Microsoft_Purview.md](Knowledge_Notes/04_Microsoft_Purview.md)**: Data governance and compliance
- **[05_Azure_Integration.md](Knowledge_Notes/05_Azure_Integration.md)**: Azure cloud platform services

### Advanced Topics
- **[06_PowerShell_Automation.md](Knowledge_Notes/06_PowerShell_Automation.md)**: Advanced scripting techniques and automation
- **[07_Windows_Server_Active_Directory.md](Knowledge_Notes/07_Windows_Server_Active_Directory.md)**: On-premises integration and hybrid identity
- **[08_Advanced_Topics.md](Knowledge_Notes/08_Advanced_Topics.md)**: Multi-tenant management, disaster recovery, and performance optimization

Each knowledge note file is self-contained and covers its topic comprehensively from beginner to advanced levels.

## 🛠️ Script Categories

### 1. User Management Scripts (`User_Management_Scripts.ps1`)

**Features:**
- Complete user lifecycle management
- Bulk user operations
- License management
- User provisioning and deprovisioning
- Department transfers and role changes

**Key Functions:**
- `New-M365User`: Create individual users
- `New-BulkUsers`: Create users from CSV
- `Update-UserProperties`: Modify user attributes
- `Move-UserToDepartment`: Transfer users between departments
- `Set-UserLicense`: Manage user licenses
- `Disable-UserAccount`: Deactivate user accounts

### 2. Intune Management Scripts (`Intune_Management_Scripts.ps1`)

**Features:**
- Device management and compliance
- Application deployment
- Configuration profile management
- Policy enforcement
- Device actions and remote management

**Key Functions:**
- `Get-IntuneDevices`: Retrieve device information
- `Invoke-DeviceAction`: Execute device actions (sync, wipe, lock)
- `New-IntuneCompliancePolicy`: Create compliance policies
- `Get-IntuneApplications`: Manage applications
- `New-AppAssignment`: Deploy applications
- `Start-IntuneMaintenance`: Automated maintenance tasks

### 3. Azure AD Management Scripts (`Azure_AD_Management_Scripts.ps1`)

**Features:**
- Group management and synchronization
- Application registration and management
- Conditional Access policies
- Security monitoring and reporting
- Risk assessment and compliance

**Key Functions:**
- `Get-AzureADGroups`: Manage security and distribution groups
- `New-AzureADGroup`: Create groups with proper configuration
- `Sync-GroupMembership`: Synchronize group membership
- `Get-AzureADApplications`: Application lifecycle management
- `New-ConditionalAccessPolicy`: Security policy creation
- `Get-RiskEvents`: Security monitoring

### 4. Purview Management Scripts (`Purview_Management_Scripts.ps1`)

**Features:**
- Data classification and labeling
- Data Loss Prevention (DLP) policies
- Retention policy management
- Compliance reporting
- Data governance automation

**Key Functions:**
- `Get-SensitivityLabels`: Manage sensitivity labels
- `New-DLPPolicy`: Create DLP policies
- `New-DLPRule`: Configure DLP rules
- `Get-RetentionPolicies`: Retention management
- `Start-DataClassification`: Automated data discovery
- `Get-ComplianceReports`: Generate compliance reports

### 5. Windows Server & AD Scripts (`Windows_Server_AD_Scripts.ps1`)

**Features:**
- Active Directory user and group management
- Organizational Unit administration
- Computer account management
- Hybrid identity synchronization
- On-premises to cloud integration

**Key Functions:**
- `Get-ADUsers`: Comprehensive user management
- `New-ADGroup`: Group lifecycle management
- `Get-ADOrganizationalUnits`: OU administration
- `Sync-ADToAzureAD`: Hybrid identity sync
- `Start-ADMaintenance`: Automated AD maintenance

## 🔧 Advanced Features

### Automation and Scheduling

All scripts include automation capabilities:

```powershell
# Schedule daily maintenance
$Action = {
    . .\Scripts\User_Management_Scripts.ps1
    Connect-M365Services
    Start-UserMaintenance -CleanupDisabledAccounts -UpdateLicenses
    Disconnect-M365Services
}

Register-ScheduledTask -TaskName "M365 Daily Maintenance" -Action $Action -Trigger (New-ScheduledTaskTrigger -Daily -At "02:00")
```

### Error Handling and Logging

Comprehensive logging and error handling:

```powershell
# All scripts include detailed logging
Write-Log "Operation completed successfully" "Success"
Write-Log "Warning: Non-critical issue detected" "Warning"
Write-Log "Error: Operation failed" "Error"
```

### Bulk Operations

Support for bulk operations with CSV import:

```powershell
# Bulk user creation from CSV
$Users = Import-Csv -Path "Users.csv"
New-BulkUsers -CSVPath "Users.csv"
```

## 📊 Reporting and Analytics

### Built-in Reporting

Each script category includes comprehensive reporting:

- **User Analytics**: License usage, account status, department distribution
- **Device Analytics**: Compliance status, platform breakdown, enrollment trends
- **Security Analytics**: Risk events, sign-in patterns, policy compliance
- **Compliance Analytics**: DLP incidents, retention status, label usage

### Custom Reports

Generate custom reports with filtering:

```powershell
# Custom user report
Get-UserReport -Department "IT" -IncludeInactive -OutputPath "IT_Detailed_Report.csv"

# Device compliance report
Get-DeviceComplianceReport -OutputPath "Device_Compliance_$(Get-Date -Format 'yyyyMMdd').csv"
```

## 🔒 Security Best Practices

### Authentication

- Use service principals for automation
- Implement least privilege access
- Enable multi-factor authentication
- Regular credential rotation

### Data Protection

- Encrypt sensitive data in scripts
- Use Azure Key Vault for secrets
- Implement proper logging and monitoring
- Regular security audits

### Compliance

- Follow organizational policies
- Maintain audit trails
- Regular compliance reporting
- Data retention management

## 🚨 Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify credentials and permissions
   - Check MFA requirements
   - Validate service principal configuration

2. **Throttling Issues**
   - Implement proper delays between operations
   - Use batch operations where possible
   - Monitor API usage limits

3. **Permission Errors**
   - Verify required roles and permissions
   - Check conditional access policies
   - Validate group memberships

### Debug Mode

Enable detailed logging:

```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"

