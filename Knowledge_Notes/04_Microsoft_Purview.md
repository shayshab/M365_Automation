# Microsoft Purview

## What is Microsoft Purview?

Microsoft Purview is a unified data governance solution that helps you manage and govern your on-premises, multi-cloud, and software-as-a-service (SaaS) data.

## Key Features

### Data Discovery and Classification
- **Automated Discovery**: Automatically discover and classify data across environments
- **Sensitivity Labels**: Classify and protect sensitive information
- **Custom Classifiers**: Create custom classification rules
- **Data Lineage**: Track data flow across systems

### Data Loss Prevention (DLP)
- **DLP Policies**: Prevent sensitive data from leaving your organization
- **DLP Rules**: Configure specific actions for different data types
- **Incident Management**: Track and respond to DLP violations
- **Policy Tips**: Educate users about data handling

### Information Protection
- **Sensitivity Labels**: Apply labels to documents and emails
- **Encryption**: Protect data at rest and in transit
- **Rights Management**: Control access and usage rights
- **Label Analytics**: Monitor label usage and effectiveness

### Compliance Management
- **Retention Policies**: Manage data retention and deletion
- **Compliance Policies**: Ensure regulatory compliance
- **Audit Logging**: Track all data access and modifications
- **Compliance Reports**: Generate compliance reports

## Data Classification

### Sensitivity Labels

#### Create Sensitivity Labels
```powershell
# Connect to Security & Compliance Center
Connect-IPPSSession

# Create sensitivity label
$Label = New-Label -DisplayName "Confidential" -Name "Confidential" -Comment "For confidential information"

# Create label with advanced settings
$AdvancedSettings = @(
    "EncryptionEnabled=true"
    "EncryptionRightsDefinitions=Company-Confidential:VIEW,EDIT"
    "LabelActions=PROTECT"
)

New-Label -DisplayName "Highly Confidential" -Name "HighlyConfidential" -AdvancedSettings $AdvancedSettings
```

#### Create Label Policy
```powershell
# Create label policy
New-LabelPolicy -Name "Global Label Policy" -Labels $Label.Identity -ExchangeLocation "All" -SharePointLocation "All"

# Create policy with specific locations
$Locations = @("https://company.sharepoint.com/sites/hr", "https://company.sharepoint.com/sites/legal")
New-LabelPolicy -Name "HR Legal Policy" -Labels $Label.Identity -SharePointLocation $Locations
```

### Custom Sensitive Information Types

#### Create Custom Sensitive Information Type
```powershell
# Create custom sensitive information type
$CustomSIT = @{
    Name = "Employee ID"
    Description = "Company employee identification numbers"
    Pattern = @(
        @{
            Pattern = "\bEMP\d{6}\b"
            Confidence = "High"
        }
    )
}

New-DlpSensitiveInformationType -Name $CustomSIT.Name -Description $CustomSIT.Description
```

## Data Loss Prevention (DLP)

### DLP Policies

#### Create DLP Policy
```powershell
# Create DLP policy
$DLPPolicy = New-DlpCompliancePolicy -Name "Financial Data Protection" -Comment "Protect financial information"

# Create policy for specific locations
$DLPPolicy = New-DlpCompliancePolicy -Name "HR Data Protection" -ExchangeLocation "All" -SharePointLocation @("https://company.sharepoint.com/sites/hr")
```

#### Create DLP Rule
```powershell
# Create DLP rule with content detection
$DLPRule = New-DlpComplianceRule -Name "Financial Data Rule" `
                                -Policy $DLPPolicy.Identity `
                                -ContentContainsSensitiveInformation @("Credit Card Number", "Bank Account Number") `
                                -BlockAccess $true `
                                -NotifyUser $true

# Create rule with custom conditions
$DLPRule = New-DlpComplianceRule -Name "Confidential Email Rule" `
                                -Policy $DLPPolicy.Identity `
                                -ContentContainsWords @("confidential", "proprietary") `
                                -BlockAccess $false `
                                -NotifyUser $true `
                                -NotifyEmail @("compliance@company.com")
```

### DLP Incident Management

#### Get DLP Incidents
```powershell
# Get DLP incidents
$Incidents = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -Operations "DLPAction"

# Get specific incident details
$IncidentDetails = $Incidents | Where-Object {$_.Operations -eq "DLPAction"} | Select-Object UserIds, ClientIP, Created, ResultStatus
```

## Retention Policies

### Create Retention Policies

#### Basic Retention Policy
```powershell
# Create retention policy
$RetentionPolicy = New-RetentionCompliancePolicy -Name "Standard Retention" -Comment "Standard retention policy"

# Create policy for specific workloads
$RetentionPolicy = New-RetentionCompliancePolicy -Name "Email Retention" -Workload @("Exchange") -ExchangeLocation "All"
```

#### Create Retention Rule
```powershell
# Create retention rule
$RetentionRule = New-RetentionComplianceRule -Name "Standard Retention Rule" `
                                           -Policy $RetentionPolicy.Identity `
                                           -RetentionDuration 2555 `
                                           -RetentionAction "KeepAndDelete"

# Create rule with content conditions
$RetentionRule = New-RetentionComplianceRule -Name "Contract Retention Rule" `
                                           -Policy $RetentionPolicy.Identity `
                                           -ContentContainsWords @("contract", "agreement") `
                                           -RetentionDuration 3650 `
                                           -RetentionAction "KeepAndDelete"
```

## Information Protection

### Rights Management

#### Configure Rights Management
```powershell
# Get current rights management configuration
Get-IRMConfiguration

# Enable rights management
Set-IRMConfiguration -InternalLicensingEnabled $true -ExternalLicensingEnabled $true
```

#### Create Rights Management Templates
```powershell
# Create custom rights management template
$RightsTemplate = @{
    Name = "Company Confidential"
    Description = "Company confidential information template"
    RightsDefinitions = @(
        @{
            Rights = @("VIEW", "EDIT")
            Users = @("Company-Confidential@company.com")
        }
    )
}

New-RmsTemplate -Name $RightsTemplate.Name -Description $RightsTemplate.Description
```

## Compliance Reporting

### Generate Compliance Reports

#### DLP Compliance Report
```powershell
function Get-DLPComplianceReport {
    $Report = @{
        Timestamp = Get-Date
        Policies = @()
        Incidents = @()
        Trends = @{}
    }
    
    # Get DLP policies
    $DLPPolicies = Get-DlpCompliancePolicy
    foreach ($Policy in $DLPPolicies) {
        $PolicyInfo = @{
            Name = $Policy.Name
            State = $Policy.State
            Mode = $Policy.Mode
            RuleCount = (Get-DlpComplianceRule -Policy $Policy.Identity).Count
        }
        $Report.Policies += $PolicyInfo
    }
    
    # Get DLP incidents (last 30 days)
    $Incidents = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -Operations "DLPAction"
    $Report.Incidents = $Incidents | Select-Object UserIds, Created, ResultStatus, Operations
    
    return $Report
}
```

#### Label Usage Report
```powershell
function Get-LabelUsageReport {
    $Labels = Get-Label
    $Report = @{
        TotalLabels = $Labels.Count
        EnabledLabels = ($Labels | Where-Object {$_.Enabled -eq $true}).Count
        DisabledLabels = ($Labels | Where-Object {$_.Enabled -eq $false}).Count
        LabelDetails = $Labels | Select-Object DisplayName, Enabled, Priority
    }
    
    return $Report
}
```

## Data Discovery

### Automated Data Discovery

#### Start Data Classification
```powershell
function Start-DataClassification {
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("Exchange", "SharePoint", "OneDrive", "Teams")]
        [string[]]$Workload = @("Exchange", "SharePoint", "OneDrive")
    )
    
    foreach ($Service in $Workload) {
        Write-Host "Starting data classification for $Service" -ForegroundColor Green
        
        # Note: Actual classification scanning is typically handled automatically
        # This function represents the concept of initiating scans
        
        # Get classification results
        $ClassificationResults = Get-DlpSensitiveInformationTypeRulePackage -Workload $Service
        Write-Host "Classification results for $Service : $($ClassificationResults.Count) items found" -ForegroundColor Yellow
    }
}
```

### Custom Data Discovery

#### Discover Sensitive Data
```powershell
function Discover-SensitiveData {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SearchQuery,
        [Parameter(Mandatory=$false)]
        [string[]]$Locations
    )
    
    $SearchParams = @{
        ContentMatchQuery = $SearchQuery
        StartDate = (Get-Date).AddDays(-30)
        EndDate = (Get-Date)
    }
    
    if ($Locations) {
        $SearchParams.ExchangeLocation = $Locations
    }
    
    $Results = Search-UnifiedAuditLog @SearchParams
    return $Results
}
```

## Automation and Maintenance

### Automated Policy Management

#### Update DLP Policies
```powershell
function Update-DLPPolicies {
    $DLPPolicies = Get-DlpCompliancePolicy
    
    foreach ($Policy in $DLPPolicies) {
        if ($Policy.State -eq "Disabled") {
            Write-Host "Enabling DLP policy: $($Policy.Name)" -ForegroundColor Yellow
            Set-DlpCompliancePolicy -Identity $Policy.Identity -State "Enabled"
        }
        
        # Check for policies without rules
        $Rules = Get-DlpComplianceRule -Policy $Policy.Identity
        if ($Rules.Count -eq 0) {
            Write-Host "Warning: Policy $($Policy.Name) has no rules" -ForegroundColor Red
        }
    }
}
```

#### Cleanup Orphaned Policies
```powershell
function Cleanup-OrphanedPolicies {
    # Find DLP policies without rules
    $DLPPolicies = Get-DlpCompliancePolicy
    $OrphanedPolicies = @()
    
    foreach ($Policy in $DLPPolicies) {
        $Rules = Get-DlpComplianceRule -Policy $Policy.Identity
        if ($Rules.Count -eq 0) {
            $OrphanedPolicies += $Policy
        }
    }
    
    Write-Host "Found $($OrphanedPolicies.Count) orphaned DLP policies" -ForegroundColor Yellow
    
    # Find retention policies without rules
    $RetentionPolicies = Get-RetentionCompliancePolicy
    $OrphanedRetentionPolicies = @()
    
    foreach ($Policy in $RetentionPolicies) {
        $Rules = Get-RetentionComplianceRule -Policy $Policy.Identity
        if ($Rules.Count -eq 0) {
            $OrphanedRetentionPolicies += $Policy
        }
    }
    
    Write-Host "Found $($OrphanedRetentionPolicies.Count) orphaned retention policies" -ForegroundColor Yellow
}
```

## Best Practices

### Data Classification
1. Start with standard sensitivity labels
2. Create custom labels for specific business needs
3. Train users on proper label usage
4. Monitor label adoption and effectiveness

### DLP Policies
1. Start with test mode policies
2. Gradually move to enforcement mode
3. Regular policy review and updates
4. Monitor false positives and adjust rules

### Retention Management
1. Align retention policies with business requirements
2. Regular review of retention periods
3. Monitor storage costs and compliance
4. Test retention policies before enforcement

### Compliance
1. Regular compliance assessments
2. Monitor regulatory requirements
3. Maintain audit trails
4. Regular policy effectiveness reviews

---

*This guide covers Microsoft Purview data governance and compliance. For advanced scenarios and integration with other M365 services, refer to the service-specific documentation.*
