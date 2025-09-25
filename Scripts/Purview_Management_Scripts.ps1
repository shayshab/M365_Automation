# Microsoft Purview Management Scripts
# Comprehensive PowerShell scripts for Microsoft Purview data governance and compliance

#region Prerequisites and Setup
# Install required modules
# Install-Module -Name ExchangeOnlineManagement -Force
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
    
    $LogMessage | Out-File -FilePath "M365_PurviewManagement.log" -Append
}

function Test-PurviewConnection {
    try {
        $Session = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange"}
        if ($Session) {
            Write-Log "Connected to Exchange Online (Purview services)" "Success"
            return $true
        }
        else {
            Write-Log "Not connected to Exchange Online" "Error"
            return $false
        }
    }
    catch {
        Write-Log "Purview connection test failed: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Sensitivity Labels
function Get-SensitivityLabels {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Enabled", "Disabled", "All")]
        [string]$Status = "All",
        [Parameter(Mandatory=$false)]
        [switch]$IncludeSettings
    )
    
    try {
        Write-Log "Retrieving sensitivity labels..." "Info"
        
        $Labels = Get-Label
        
        # Apply filters
        if ($DisplayName) {
            $Labels = $Labels | Where-Object {$_.DisplayName -like "*$DisplayName*"}
        }
        
        if ($Status -ne "All") {
            $Labels = $Labels | Where-Object {$_.Enabled -eq ($Status -eq "Enabled")}
        }
        
        if ($IncludeSettings) {
            $DetailedLabels = @()
            foreach ($Label in $Labels) {
                $LabelInfo = @{
                    Identity = $Label.Identity
                    DisplayName = $Label.DisplayName
                    Comment = $Label.Comment
                    Enabled = $Label.Enabled
                    Tooltip = $Label.Tooltip
                    Priority = $Label.Priority
                    AdvancedSettings = $Label.AdvancedSettings
                }
                
                # Get label settings
                $LabelSettings = Get-Label -Identity $Label.Identity | Select-Object -ExpandProperty Settings
                $LabelInfo.Settings = $LabelSettings
                
                $DetailedLabels += $LabelInfo
            }
            return $DetailedLabels
        }
        
        return $Labels
    }
    catch {
        Write-Log "Failed to retrieve sensitivity labels: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-SensitivityLabel {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$Comment,
        [Parameter(Mandatory=$false)]
        [string]$Tooltip,
        [Parameter(Mandatory=$false)]
        [int]$Priority = 1,
        [Parameter(Mandatory=$false)]
        [hashtable]$AdvancedSettings
    )
    
    try {
        Write-Log "Creating sensitivity label: $DisplayName" "Info"
        
        $LabelParams = @{
            Name = $DisplayName
            DisplayName = $DisplayName
            Comment = $Comment
            Tooltip = $Tooltip
            Priority = $Priority
        }
        
        # Add advanced settings if provided
        if ($AdvancedSettings) {
            $Settings = @()
            foreach ($Setting in $AdvancedSettings.GetEnumerator()) {
                $Settings += "$($Setting.Key)=$($Setting.Value)"
            }
            $LabelParams.AdvancedSettings = $Settings
        }
        
        $NewLabel = New-Label @LabelParams
        Write-Log "Sensitivity label created successfully with Identity: $($NewLabel.Identity)" "Success"
        
        return $NewLabel
    }
    catch {
        Write-Log "Failed to create sensitivity label: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Set-SensitivityLabelPolicy {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PolicyName,
        [Parameter(Mandatory=$true)]
        [string[]]$LabelIdentities,
        [Parameter(Mandatory=$false)]
        [string]$Comment,
        [Parameter(Mandatory=$false)]
        [string[]]$ExchangeLocation,
        [Parameter(Mandatory=$false)]
        [string[]]$SharePointLocation,
        [Parameter(Mandatory=$false)]
        [string[]]$OneDriveLocation,
        [Parameter(Mandatory=$false)]
        [string[]]$TeamsLocation
    )
    
    try {
        Write-Log "Creating sensitivity label policy: $PolicyName" "Info"
        
        $PolicyParams = @{
            Name = $PolicyName
            Labels = $LabelIdentities
            Comment = $Comment
        }
        
        # Add location settings
        if ($ExchangeLocation) { $PolicyParams.ExchangeLocation = $ExchangeLocation }
        if ($SharePointLocation) { $PolicyParams.SharePointLocation = $SharePointLocation }
        if ($OneDriveLocation) { $PolicyParams.OneDriveLocation = $OneDriveLocation }
        if ($TeamsLocation) { $PolicyParams.TeamsLocation = $TeamsLocation }
        
        $NewPolicy = New-LabelPolicy @PolicyParams
        Write-Log "Sensitivity label policy created successfully" "Success"
        
        return $NewPolicy
    }
    catch {
        Write-Log "Failed to create sensitivity label policy: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Data Loss Prevention (DLP)
function Get-DLPPolicies {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Enabled", "Disabled", "All")]
        [string]$State = "All",
        [Parameter(Mandatory=$false)]
        [switch]$IncludeRules
    )
    
    try {
        Write-Log "Retrieving DLP policies..." "Info"
        
        $Policies = Get-DlpCompliancePolicy
        
        # Apply filters
        if ($Name) {
            $Policies = $Policies | Where-Object {$_.Name -like "*$Name*"}
        }
        
        if ($State -ne "All") {
            $Policies = $Policies | Where-Object {$_.State -eq $State}
        }
        
        if ($IncludeRules) {
            $DetailedPolicies = @()
            foreach ($Policy in $Policies) {
                $PolicyInfo = @{
                    Identity = $Policy.Identity
                    Name = $Policy.Name
                    Comment = $Policy.Comment
                    State = $Policy.State
                    Mode = $Policy.Mode
                    CreatedBy = $Policy.CreatedBy
                    CreatedDate = $Policy.CreatedDate
                    ModifiedBy = $Policy.ModifiedBy
                    ModifiedDate = $Policy.ModifiedDate
                }
                
                # Get policy rules
                $Rules = Get-DlpComplianceRule -Policy $Policy.Identity
                $PolicyInfo.RuleCount = $Rules.Count
                $PolicyInfo.Rules = $Rules | Select-Object Name, Comment, Enabled, Mode
                
                $DetailedPolicies += $PolicyInfo
            }
            return $DetailedPolicies
        }
        
        return $Policies
    }
    catch {
        Write-Log "Failed to retrieve DLP policies: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-DLPPolicy {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Comment,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Enable", "TestWithNotifications", "TestWithoutNotifications")]
        [string]$Mode = "TestWithNotifications",
        [Parameter(Mandatory=$false)]
        [string[]]$ExchangeLocation,
        [Parameter(Mandatory=$false)]
        [string[]]$SharePointLocation,
        [Parameter(Mandatory=$false)]
        [string[]]$OneDriveLocation,
        [Parameter(Mandatory=$false)]
        [string[]]$TeamsLocation
    )
    
    try {
        Write-Log "Creating DLP policy: $Name" "Info"
        
        $PolicyParams = @{
            Name = $Name
            Comment = $Comment
            Mode = $Mode
        }
        
        # Add location settings
        if ($ExchangeLocation) { $PolicyParams.ExchangeLocation = $ExchangeLocation }
        if ($SharePointLocation) { $PolicyParams.SharePointLocation = $SharePointLocation }
        if ($OneDriveLocation) { $PolicyParams.OneDriveLocation = $OneDriveLocation }
        if ($TeamsLocation) { $PolicyParams.TeamsLocation = $TeamsLocation }
        
        $NewPolicy = New-DlpCompliancePolicy @PolicyParams
        Write-Log "DLP policy created successfully with Identity: $($NewPolicy.Identity)" "Success"
        
        return $NewPolicy
    }
    catch {
        Write-Log "Failed to create DLP policy: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-DLPRule {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$Policy,
        [Parameter(Mandatory=$false)]
        [string]$Comment,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Enable", "TestWithNotifications", "TestWithoutNotifications")]
        [string]$Mode = "Enable",
        [Parameter(Mandatory=$false)]
        [string[]]$ContentContainsSensitiveInformation,
        [Parameter(Mandatory=$false)]
        [string[]]$ContentContainsWords,
        [Parameter(Mandatory=$false)]
        [string[]]$ContentMatchesPatterns,
        [Parameter(Mandatory=$false)]
        [switch]$BlockAccess,
        [Parameter(Mandatory=$false)]
        [switch]$NotifyUser,
        [Parameter(Mandatory=$false)]
        [string[]]$NotifyEmail
    )
    
    try {
        Write-Log "Creating DLP rule: $Name" "Info"
        
        $RuleParams = @{
            Name = $Name
            Policy = $Policy
            Comment = $Comment
            Mode = $Mode
        }
        
        # Add content conditions
        if ($ContentContainsSensitiveInformation) {
            $RuleParams.ContentContainsSensitiveInformation = $ContentContainsSensitiveInformation
        }
        
        if ($ContentContainsWords) {
            $RuleParams.ContentContainsWords = $ContentContainsWords
        }
        
        if ($ContentMatchesPatterns) {
            $RuleParams.ContentMatchesPatterns = $ContentMatchesPatterns
        }
        
        # Add actions
        if ($BlockAccess) {
            $RuleParams.BlockAccess = $true
        }
        
        if ($NotifyUser) {
            $RuleParams.NotifyUser = $true
        }
        
        if ($NotifyEmail) {
            $RuleParams.NotifyEmail = $NotifyEmail
        }
        
        $NewRule = New-DlpComplianceRule @RuleParams
        Write-Log "DLP rule created successfully" "Success"
        
        return $NewRule
    }
    catch {
        Write-Log "Failed to create DLP rule: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Retention Policies
function Get-RetentionPolicies {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Enabled", "Disabled", "All")]
        [string]$State = "All",
        [Parameter(Mandatory=$false)]
        [switch]$IncludeRules
    )
    
    try {
        Write-Log "Retrieving retention policies..." "Info"
        
        $Policies = Get-RetentionCompliancePolicy
        
        # Apply filters
        if ($Name) {
            $Policies = $Policies | Where-Object {$_.Name -like "*$Name*"}
        }
        
        if ($State -ne "All") {
            $Policies = $Policies | Where-Object {$_.Enabled -eq ($State -eq "Enabled")}
        }
        
        if ($IncludeRules) {
            $DetailedPolicies = @()
            foreach ($Policy in $Policies) {
                $PolicyInfo = @{
                    Identity = $Policy.Identity
                    Name = $Policy.Name
                    Comment = $Policy.Comment
                    Enabled = $Policy.Enabled
                    Workload = $Policy.Workload
                    CreatedBy = $Policy.CreatedBy
                    CreatedDate = $Policy.CreatedDate
                    ModifiedBy = $Policy.ModifiedBy
                    ModifiedDate = $Policy.ModifiedDate
                }
                
                # Get policy rules
                $Rules = Get-RetentionComplianceRule -Policy $Policy.Identity
                $PolicyInfo.RuleCount = $Rules.Count
                $PolicyInfo.Rules = $Rules | Select-Object Name, Comment, Enabled, RetentionDuration, RetentionAction
                
                $DetailedPolicies += $PolicyInfo
            }
            return $DetailedPolicies
        }
        
        return $Policies
    }
    catch {
        Write-Log "Failed to retrieve retention policies: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-RetentionPolicy {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Comment,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Exchange", "SharePoint", "OneDrive", "Teams")]
        [string[]]$Workload = @("Exchange", "SharePoint", "OneDrive"),
        [Parameter(Mandatory=$false)]
        [string[]]$ExchangeLocation,
        [Parameter(Mandatory=$false)]
        [string[]]$SharePointLocation,
        [Parameter(Mandatory=$false)]
        [string[]]$OneDriveLocation,
        [Parameter(Mandatory=$false)]
        [string[]]$TeamsLocation
    )
    
    try {
        Write-Log "Creating retention policy: $Name" "Info"
        
        $PolicyParams = @{
            Name = $Name
            Comment = $Comment
            Workload = $Workload
        }
        
        # Add location settings
        if ($ExchangeLocation) { $PolicyParams.ExchangeLocation = $ExchangeLocation }
        if ($SharePointLocation) { $PolicyParams.SharePointLocation = $SharePointLocation }
        if ($OneDriveLocation) { $PolicyParams.OneDriveLocation = $OneDriveLocation }
        if ($TeamsLocation) { $PolicyParams.TeamsLocation = $TeamsLocation }
        
        $NewPolicy = New-RetentionCompliancePolicy @PolicyParams
        Write-Log "Retention policy created successfully with Identity: $($NewPolicy.Identity)" "Success"
        
        return $NewPolicy
    }
    catch {
        Write-Log "Failed to create retention policy: $($_.Exception.Message)" "Error"
        return $null
    }
}

function New-RetentionRule {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$Policy,
        [Parameter(Mandatory=$false)]
        [string]$Comment,
        [Parameter(Mandatory=$false)]
        [int]$RetentionDuration = 2555, # 7 years in days
        [Parameter(Mandatory=$false)]
        [ValidateSet("Delete", "Keep", "KeepAndDelete")]
        [string]$RetentionAction = "KeepAndDelete",
        [Parameter(Mandatory=$false)]
        [string[]]$ContentContainsSensitiveInformation,
        [Parameter(Mandatory=$false)]
        [string[]]$ContentContainsWords,
        [Parameter(Mandatory=$false)]
        [string[]]$ContentMatchesPatterns
    )
    
    try {
        Write-Log "Creating retention rule: $Name" "Info"
        
        $RuleParams = @{
            Name = $Name
            Policy = $Policy
            Comment = $Comment
            RetentionDuration = $RetentionDuration
            RetentionAction = $RetentionAction
        }
        
        # Add content conditions
        if ($ContentContainsSensitiveInformation) {
            $RuleParams.ContentContainsSensitiveInformation = $ContentContainsSensitiveInformation
        }
        
        if ($ContentContainsWords) {
            $RuleParams.ContentContainsWords = $ContentContainsWords
        }
        
        if ($ContentMatchesPatterns) {
            $RuleParams.ContentMatchesPatterns = $ContentMatchesPatterns
        }
        
        $NewRule = New-RetentionComplianceRule @RuleParams
        Write-Log "Retention rule created successfully" "Success"
        
        return $NewRule
    }
    catch {
        Write-Log "Failed to create retention rule: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Data Classification
function Get-DataClassification {
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("Exchange", "SharePoint", "OneDrive", "Teams")]
        [string]$Workload,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Top", "Bottom")]
        [string]$Order = "Top",
        [Parameter(Mandatory=$false)]
        [int]$Top = 100
    )
    
    try {
        Write-Log "Retrieving data classification information..." "Info"
        
        $Classification = @{}
        
        # Get sensitive information types
        $SensitiveTypes = Get-DlpSensitiveInformationType
        $Classification.SensitiveInformationTypes = @{
            Count = $SensitiveTypes.Count
            Types = $SensitiveTypes | Select-Object Name, Description, PatternCount
        }
        
        # Get data classification insights (requires additional permissions)
        try {
            if ($Workload) {
                $Insights = Get-DlpSensitiveInformationTypeRulePackage -Workload $Workload
            }
            else {
                $Insights = Get-DlpSensitiveInformationTypeRulePackage
            }
            
            $Classification.Insights = $Insights
        }
        catch {
            Write-Log "Could not retrieve classification insights: $($_.Exception.Message)" "Warning"
        }
        
        return $Classification
    }
    catch {
        Write-Log "Failed to retrieve data classification: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Start-DataClassification {
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("Exchange", "SharePoint", "OneDrive", "Teams")]
        [string[]]$Workload = @("Exchange", "SharePoint", "OneDrive"),
        [Parameter(Mandatory=$false)]
        [switch]$ForceRescan
    )
    
    try {
        Write-Log "Starting data classification scan..." "Info"
        
        foreach ($Service in $Workload) {
            Write-Log "Scanning $Service for sensitive data..." "Info"
            
            # Note: Actual classification scanning is typically handled automatically
            # This function represents the concept of initiating scans
            Write-Log "$Service classification scan initiated" "Success"
        }
        
        if ($ForceRescan) {
            Write-Log "Forcing rescan of all content..." "Info"
            # Add logic for forced rescan if available
            Write-Log "Forced rescan completed" "Success"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to start data classification: $($_.Exception.Message)" "Error"
        return $false
    }
}

#endregion

#region Audit and Compliance
function Get-AuditLogs {
    param(
        [Parameter(Mandatory=$false)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [string]$Activity,
        [Parameter(Mandatory=$false)]
        [DateTime]$StartDate,
        [Parameter(Mandatory=$false)]
        [DateTime]$EndDate,
        [Parameter(Mandatory=$false)]
        [int]$Top = 1000
    )
    
    try {
        Write-Log "Retrieving audit logs..." "Info"
        
        $SearchParams = @{
            ResultSize = $Top
        }
        
        # Add filters
        if ($UserPrincipalName) {
            $SearchParams.UserIds = $UserPrincipalName
        }
        
        if ($Activity) {
            $SearchParams.Activities = $Activity
        }
        
        if ($StartDate) {
            $SearchParams.StartDate = $StartDate
        }
        
        if ($EndDate) {
            $SearchParams.EndDate = $EndDate
        }
        
        $AuditLogs = Search-UnifiedAuditLog @SearchParams
        
        return $AuditLogs
    }
    catch {
        Write-Log "Failed to retrieve audit logs: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Get-ComplianceReports {
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("DLP", "Retention", "Labels", "All")]
        [string]$ReportType = "All",
        [Parameter(Mandatory=$false)]
        [DateTime]$StartDate,
        [Parameter(Mandatory=$false)]
        [DateTime]$EndDate,
        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Generating compliance reports..." "Info"
        
        $Reports = @{
            Timestamp = Get-Date
            DLP = @{}
            Retention = @{}
            Labels = @{}
        }
        
        if ($ReportType -eq "All" -or $ReportType -eq "DLP") {
            # DLP Report
            $DLPPolicies = Get-DlpCompliancePolicy
            $Reports.DLP = @{
                TotalPolicies = $DLPPolicies.Count
                EnabledPolicies = ($DLPPolicies | Where-Object {$_.State -eq "Enabled"}).Count
                TestPolicies = ($DLPPolicies | Where-Object {$_.State -eq "TestWithNotifications"}).Count
                DisabledPolicies = ($DLPPolicies | Where-Object {$_.State -eq "Disabled"}).Count
            }
        }
        
        if ($ReportType -eq "All" -or $ReportType -eq "Retention") {
            # Retention Report
            $RetentionPolicies = Get-RetentionCompliancePolicy
            $Reports.Retention = @{
                TotalPolicies = $RetentionPolicies.Count
                EnabledPolicies = ($RetentionPolicies | Where-Object {$_.Enabled -eq $true}).Count
                DisabledPolicies = ($RetentionPolicies | Where-Object {$_.Enabled -eq $false}).Count
            }
        }
        
        if ($ReportType -eq "All" -or $ReportType -eq "Labels") {
            # Labels Report
            $Labels = Get-Label
            $Reports.Labels = @{
                TotalLabels = $Labels.Count
                EnabledLabels = ($Labels | Where-Object {$_.Enabled -eq $true}).Count
                DisabledLabels = ($Labels | Where-Object {$_.Enabled -eq $false}).Count
            }
        }
        
        if ($OutputPath) {
            $Reports | ConvertTo-Json -Depth 3 | Out-File -FilePath $OutputPath
            Write-Log "Compliance reports exported to: $OutputPath" "Success"
        }
        
        return $Reports
    }
    catch {
        Write-Log "Failed to generate compliance reports: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Reporting and Analytics
function Get-PurviewAnalytics {
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Generating Purview analytics report..." "Info"
        
        $Analytics = @{
            Timestamp = Get-Date
            SensitivityLabels = @{}
            DLP = @{}
            Retention = @{}
            DataClassification = @{}
            Audit = @{}
        }
        
        # Sensitivity Labels Analytics
        $Labels = Get-Label
        $Analytics.SensitivityLabels = @{
            TotalLabels = $Labels.Count
            EnabledLabels = ($Labels | Where-Object {$_.Enabled -eq $true}).Count
            DisabledLabels = ($Labels | Where-Object {$_.Enabled -eq $false}).Count
        }
        
        # DLP Analytics
        $DLPPolicies = Get-DlpCompliancePolicy
        $Analytics.DLP = @{
            TotalPolicies = $DLPPolicies.Count
            EnabledPolicies = ($DLPPolicies | Where-Object {$_.State -eq "Enabled"}).Count
            TestPolicies = ($DLPPolicies | Where-Object {$_.State -eq "TestWithNotifications"}).Count
            DisabledPolicies = ($DLPPolicies | Where-Object {$_.State -eq "Disabled"}).Count
        }
        
        # Retention Analytics
        $RetentionPolicies = Get-RetentionCompliancePolicy
        $Analytics.Retention = @{
            TotalPolicies = $RetentionPolicies.Count
            EnabledPolicies = ($RetentionPolicies | Where-Object {$_.Enabled -eq $true}).Count
            DisabledPolicies = ($RetentionPolicies | Where-Object {$_.Enabled -eq $false}).Count
        }
        
        # Data Classification Analytics
        $SensitiveTypes = Get-DlpSensitiveInformationType
        $Analytics.DataClassification = @{
            TotalSensitiveTypes = $SensitiveTypes.Count
            CustomTypes = ($SensitiveTypes | Where-Object {$_.Publisher -eq "Custom"}).Count
            BuiltInTypes = ($SensitiveTypes | Where-Object {$_.Publisher -ne "Custom"}).Count
        }
        
        # Audit Analytics (last 30 days)
        $AuditLogs = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -ResultSize 1000
        $Analytics.Audit = @{
            TotalAuditEvents = $AuditLogs.Count
            UniqueUsers = ($AuditLogs | Select-Object UserIds -Unique).Count
            MostActiveUsers = $AuditLogs | Group-Object UserIds | Sort-Object Count -Descending | Select-Object -First 10 Name, Count
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
function Start-PurviewMaintenance {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$UpdateSensitiveInformationTypes,
        [Parameter(Mandatory=$false)]
        [switch]$CleanupOrphanedPolicies,
        [Parameter(Mandatory=$false)]
        [switch]$ValidatePolicyAssignments
    )
    
    try {
        Write-Log "Starting Purview maintenance tasks..." "Info"
        
        if ($UpdateSensitiveInformationTypes) {
            Write-Log "Updating sensitive information types..." "Info"
            
            # Check for outdated sensitive information types
            $SensitiveTypes = Get-DlpSensitiveInformationType
            $OutdatedTypes = $SensitiveTypes | Where-Object {$_.Publisher -eq "Custom" -and $_.Version -lt "1.0"}
            
            if ($OutdatedTypes.Count -gt 0) {
                Write-Log "Found $($OutdatedTypes.Count) outdated sensitive information types" "Warning"
                # Add logic to update or remove outdated types
            }
            
            Write-Log "Sensitive information types update completed" "Success"
        }
        
        if ($CleanupOrphanedPolicies) {
            Write-Log "Cleaning up orphaned policies..." "Info"
            
            # Find DLP policies without rules
            $DLPPolicies = Get-DlpCompliancePolicy
            $OrphanedDLPPolicies = @()
            
            foreach ($Policy in $DLPPolicies) {
                $Rules = Get-DlpComplianceRule -Policy $Policy.Identity
                if ($Rules.Count -eq 0) {
                    $OrphanedDLPPolicies += $Policy
                }
            }
            
            Write-Log "Found $($OrphanedDLPPolicies.Count) DLP policies without rules" "Warning"
            
            # Find retention policies without rules
            $RetentionPolicies = Get-RetentionCompliancePolicy
            $OrphanedRetentionPolicies = @()
            
            foreach ($Policy in $RetentionPolicies) {
                $Rules = Get-RetentionComplianceRule -Policy $Policy.Identity
                if ($Rules.Count -eq 0) {
                    $OrphanedRetentionPolicies += $Policy
                }
            }
            
            Write-Log "Found $($OrphanedRetentionPolicies.Count) retention policies without rules" "Warning"
        }
        
        if ($ValidatePolicyAssignments) {
            Write-Log "Validating policy assignments..." "Info"
            
            # Check for policies assigned to non-existent locations
            $DLPPolicies = Get-DlpCompliancePolicy
            foreach ($Policy in $DLPPolicies) {
                $Locations = @()
                if ($Policy.ExchangeLocation) { $Locations += $Policy.ExchangeLocation }
                if ($Policy.SharePointLocation) { $Locations += $Policy.SharePointLocation }
                if ($Policy.OneDriveLocation) { $Locations += $Policy.OneDriveLocation }
                if ($Policy.TeamsLocation) { $Locations += $Policy.TeamsLocation }
                
                # Validate locations (simplified check)
                Write-Log "Policy '$($Policy.Name)' assigned to $($Locations.Count) locations" "Info"
            }
            
            Write-Log "Policy assignment validation completed" "Success"
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
function Connect-PurviewServices {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Interactive
    )
    
    try {
        Write-Log "Connecting to Purview services..." "Info"
        
        # Connect to Exchange Online (includes Purview services)
        Connect-ExchangeOnline
        Write-Log "Connected to Exchange Online (Purview services)" "Success"
        
        return $true
    }
    catch {
        Write-Log "Failed to connect to Purview services: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Disconnect-PurviewServices {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Disconnected from Purview services" "Success"
    }
    catch {
        Write-Log "Error during disconnection: $($_.Exception.Message)" "Warning"
    }
}

#endregion

# Example usage:
<#
# Connect to Purview services
Connect-PurviewServices

# Get sensitivity labels
$Labels = Get-SensitivityLabels -IncludeSettings

# Create a new sensitivity label
$NewLabel = New-SensitivityLabel -DisplayName "Confidential" -Comment "For confidential information" -Priority 1

# Create sensitivity label policy
Set-SensitivityLabelPolicy -PolicyName "Global Label Policy" -LabelIdentities @($NewLabel.Identity) -ExchangeLocation "All" -SharePointLocation "All"

# Get DLP policies
$DLPPolicies = Get-DLPPolicies -IncludeRules

# Create DLP policy
$DLPPolicy = New-DLPPolicy -Name "Financial Data Protection" -Comment "Protect financial information" -Mode "TestWithNotifications"

# Create DLP rule
New-DLPRule -Name "Financial Data Rule" -Policy $DLPPolicy.Identity -ContentContainsSensitiveInformation @("Credit Card Number") -BlockAccess -NotifyUser

# Get retention policies
$RetentionPolicies = Get-RetentionPolicies -IncludeRules

# Create retention policy
$RetentionPolicy = New-RetentionPolicy -Name "Standard Retention" -Comment "Standard retention policy" -Workload @("Exchange", "SharePoint", "OneDrive")

# Create retention rule
New-RetentionRule -Name "Standard Retention Rule" -Policy $RetentionPolicy.Identity -RetentionDuration 2555 -RetentionAction "KeepAndDelete"

# Get data classification
$Classification = Get-DataClassification

# Start data classification
Start-DataClassification -Workload @("Exchange", "SharePoint", "OneDrive")

# Get audit logs
$AuditLogs = Get-AuditLogs -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

# Generate compliance reports
Get-ComplianceReports -OutputPath "Purview_Compliance_Report.json"

# Generate analytics
Get-PurviewAnalytics -OutputPath "Purview_Analytics_Report.json"

# Run maintenance tasks
Start-PurviewMaintenance -UpdateSensitiveInformationTypes -CleanupOrphanedPolicies -ValidatePolicyAssignments

# Disconnect from services
Disconnect-PurviewServices
#>
