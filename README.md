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
