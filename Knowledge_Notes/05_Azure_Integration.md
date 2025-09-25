# Azure Integration

## Understanding Azure Services

Azure provides various services that integrate with M365 for enhanced functionality and hybrid cloud scenarios.

## Key Integration Points

### Identity and Access Management
- **Azure Active Directory Domain Services**: Managed domain services in the cloud
- **Azure AD B2B/B2C**: External user collaboration and customer identity management
- **Azure AD Connect**: Synchronize on-premises Active Directory with Azure AD
- **Azure AD Privileged Identity Management**: Just-in-time access management

### Compute Services
- **Azure Virtual Machines**: Run Windows Server and Linux VMs in the cloud
- **Azure Virtual Desktop**: Virtual desktop infrastructure (VDI) solution
- **Azure Container Instances**: Run containers without managing infrastructure
- **Azure Kubernetes Service**: Managed Kubernetes container orchestration

### Storage and Backup
- **Azure Storage**: Blob, file, table, and queue storage
- **Azure Backup**: Backup M365 data and on-premises resources
- **Azure Site Recovery**: Disaster recovery and business continuity
- **Azure Files**: Managed file shares in the cloud

### Networking
- **Azure Virtual Network**: Isolated network infrastructure
- **Azure VPN Gateway**: Connect on-premises to Azure
- **Azure ExpressRoute**: Dedicated private connection to Azure
- **Azure Load Balancer**: Distribute network traffic

## Basic Azure Setup

### Connect to Azure
```powershell
# Install Azure PowerShell module
Install-Module -Name Az -Force

# Connect to Azure
Connect-AzAccount

# Connect to specific tenant
Connect-AzAccount -TenantId "your-tenant-id"

# Connect with service principal
$SecurePassword = ConvertTo-SecureString "password" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ("app-id", $SecurePassword)
Connect-AzAccount -ServicePrincipal -Credential $Credential -TenantId "tenant-id"
```

### Create Resource Groups
```powershell
# Create resource group
New-AzResourceGroup -Name "M365-Resources" -Location "East US"

# Get resource groups
Get-AzResourceGroup

# Remove resource group
Remove-AzResourceGroup -Name "M365-Resources" -Force
```

## Azure Virtual Machines

### Create Virtual Machine
```powershell
# Create virtual network
$VNet = New-AzVirtualNetwork -ResourceGroupName "M365-Resources" `
                            -Name "M365-VNet" `
                            -Location "East US" `
                            -AddressPrefix "10.0.0.0/16"

# Create subnet
$Subnet = Add-AzVirtualNetworkSubnetConfig -Name "default" `
                                          -AddressPrefix "10.0.1.0/24" `
                                          -VirtualNetwork $VNet

# Update virtual network
$VNet | Set-AzVirtualNetwork

# Create public IP
$PublicIP = New-AzPublicIpAddress -ResourceGroupName "M365-Resources" `
                                  -Name "M365-VM-PublicIP" `
                                  -Location "East US" `
                                  -AllocationMethod Static

# Create network security group
$NSG = New-AzNetworkSecurityGroup -ResourceGroupName "M365-Resources" `
                                  -Name "M365-VM-NSG" `
                                  -Location "East US"

# Add RDP rule
$RDPRule = New-AzNetworkSecurityRuleConfig -Name "RDP" `
                                           -Description "Allow RDP" `
                                           -Access Allow `
                                           -Protocol Tcp `
                                           -Direction Inbound `
                                           -Priority 1000 `
                                           -SourceAddressPrefix * `
                                           -SourcePortRange * `
                                           -DestinationAddressPrefix * `
                                           -DestinationPortRange 3389

$NSG.SecurityRules.Add($RDPRule)
$NSG | Set-AzNetworkSecurityGroup

# Create virtual machine
$VMConfig = New-AzVMConfig -VMName "M365-VM" -VMSize "Standard_B2s"
$VMConfig = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName "M365-VM" -Credential (Get-Credential)
$VMConfig = Set-AzVMSourceImage -VM $VMConfig -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2019-Datacenter" -Version "latest"
$VMConfig = Set-AzVMOSDisk -VM $VMConfig -Name "M365-VM-OSDisk" -DiskSizeInGB 128 -CreateOption FromImage -StorageAccountType "Premium_LRS"
$VMConfig = Add-AzVMNetworkInterface -VM $VMConfig -Id (New-AzNetworkInterface -ResourceGroupName "M365-Resources" -Name "M365-VM-NIC" -Location "East US" -SubnetId $Subnet.Id -PublicIpAddressId $PublicIP.Id -NetworkSecurityGroupId $NSG.Id).Id

New-AzVM -ResourceGroupName "M365-Resources" -Location "East US" -VM $VMConfig
```

### Manage Virtual Machines
```powershell
# Get all VMs
Get-AzVM

# Get VM by name
Get-AzVM -ResourceGroupName "M365-Resources" -Name "M365-VM"

# Start VM
Start-AzVM -ResourceGroupName "M365-Resources" -Name "M365-VM"

# Stop VM
Stop-AzVM -ResourceGroupName "M365-Resources" -Name "M365-VM"

# Restart VM
Restart-AzVM -ResourceGroupName "M365-Resources" -Name "M365-VM"

# Remove VM
Remove-AzVM -ResourceGroupName "M365-Resources" -Name "M365-VM" -Force
```

## Azure Active Directory Domain Services

### Enable Azure AD Domain Services
```powershell
# Note: Azure AD Domain Services is typically enabled through the Azure portal
# PowerShell commands for management after enablement

# Get Azure AD Domain Services
Get-AzADDomainService -ResourceGroupName "M365-Resources" -Name "company-aadds"

# Update Azure AD Domain Services
$AADDS = Get-AzADDomainService -ResourceGroupName "M365-Resources" -Name "company-aadds"
$AADDS.DomainConfigurationType = "FullySynced"
Set-AzADDomainService -ResourceGroupName "M365-Resources" -Name "company-aadds" -DomainService $AADDS
```

## Azure Backup

### Configure Azure Backup
```powershell
# Create recovery services vault
$Vault = New-AzRecoveryServicesVault -ResourceGroupName "M365-Resources" -Name "M365-Backup-Vault" -Location "East US"

# Set backup storage redundancy
Set-AzRecoveryServicesBackupProperty -Vault $Vault -BackupStorageRedundancy GeoRedundant

# Get backup policies
Get-AzRecoveryServicesBackupPolicy -Vault $Vault

# Create backup policy
$BackupPolicy = New-AzRecoveryServicesBackupProtectionPolicy -Vault $Vault -Name "M365-Backup-Policy" -WorkloadType "AzureVM" -BackupManagementType "AzureVM" -SchedulePolicy (New-AzRecoveryServicesBackupSchedulePolicyObject -ScheduleRunFrequency "Daily" -ScheduleRunTimes "02:00") -RetentionPolicy (New-AzRecoveryServicesBackupRetentionPolicyObject -DailyRetentionDuration 30)
```

### Backup M365 Data
```powershell
# Note: M365 backup is typically handled through Microsoft 365 Backup or third-party solutions
# Azure Backup primarily handles Azure resources

# Get backup items
Get-AzRecoveryServicesBackupItem -Vault $Vault -WorkloadType "AzureVM"

# Start backup job
Backup-AzRecoveryServicesBackupItem -Vault $Vault -Item $BackupItem
```

## Azure Monitor

### Set Up Monitoring
```powershell
# Create log analytics workspace
$Workspace = New-AzOperationalInsightsWorkspace -ResourceGroupName "M365-Resources" -Name "M365-Monitoring-Workspace" -Location "East US"

# Create action group for alerts
$ActionGroup = New-AzActionGroup -ResourceGroupName "M365-Resources" -Name "M365-Alerts" -ShortName "M365Alert"

# Add email action
Set-AzActionGroup -ResourceGroupName "M365-Resources" -Name "M365-Alerts" -EmailReceiver @{Name="admin"; EmailAddress="admin@company.com"}

# Create metric alert
$AlertRule = New-AzMetricAlertRule -Name "High CPU Usage" -Location "East US" -ResourceGroup "M365-Resources" -TargetResourceId "/subscriptions/subscription-id/resourceGroups/M365-Resources/providers/Microsoft.Compute/virtualMachines/M365-VM" -MetricName "Percentage CPU" -Operator GreaterThan -Threshold 80 -WindowSize 00:05:00 -TimeAggregationOperator Average -Action $ActionGroup.Id
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

# Update Azure AD Connect
# Note: Updates are typically done through the Azure AD Connect wizard
```

### Hybrid Exchange
```powershell
# Configure hybrid Exchange
# Note: This is typically done through the Hybrid Configuration Wizard
# PowerShell commands for post-configuration management

# Get hybrid configuration
Get-HybridConfiguration

# Test hybrid connectivity
Test-HybridConnectivity -ClientAccessServer "mail.company.com"
```

## Cost Management

### Monitor Azure Costs
```powershell
# Get resource group costs
Get-AzConsumptionUsageDetail -BillingPeriodName "202301" | Where-Object {$_.ResourceGroup -eq "M365-Resources"}

# Get subscription costs
Get-AzConsumptionUsageDetail -BillingPeriodName "202301"

# Create cost alert
$CostAlert = New-AzActionGroup -ResourceGroupName "M365-Resources" -Name "Cost-Alerts" -ShortName "CostAlert"
Set-AzActionGroup -ResourceGroupName "M365-Resources" -Name "Cost-Alerts" -EmailReceiver @{Name="finance"; EmailAddress="finance@company.com"}
```

## Security and Compliance

### Azure Security Center
```powershell
# Get security recommendations
Get-AzSecurityTask -ResourceGroupName "M365-Resources"

# Get security alerts
Get-AzSecurityAlert -ResourceGroupName "M365-Resources"

# Enable security monitoring
Set-AzSecurityContact -Email "security@company.com" -AlertAdmin -NotifyOnAlert
```

### Azure Key Vault
```powershell
# Create Key Vault
$KeyVault = New-AzKeyVault -VaultName "M365-KeyVault" -ResourceGroupName "M365-Resources" -Location "East US"

# Set access policy
Set-AzKeyVaultAccessPolicy -VaultName "M365-KeyVault" -UserPrincipalName "admin@company.com" -PermissionsToSecrets "Get,Set,List,Delete"

# Store secret
Set-AzKeyVaultSecret -VaultName "M365-KeyVault" -Name "DatabasePassword" -SecretValue (ConvertTo-SecureString "Password123!" -AsPlainText -Force)

# Retrieve secret
Get-AzKeyVaultSecret -VaultName "M365-KeyVault" -Name "DatabasePassword"
```

## Automation and Monitoring

### Azure Automation
```powershell
# Create automation account
$AutomationAccount = New-AzAutomationAccount -ResourceGroupName "M365-Resources" -Name "M365-Automation" -Location "East US"

# Create runbook
$Runbook = New-AzAutomationRunbook -ResourceGroupName "M365-Resources" -AutomationAccountName "M365-Automation" -Name "M365-Maintenance" -Type PowerShell

# Start runbook job
Start-AzAutomationRunbook -ResourceGroupName "M365-Resources" -AutomationAccountName "M365-Automation" -Name "M365-Maintenance"
```

### Resource Monitoring
```powershell
function Get-AzureResourceHealth {
    $Resources = Get-AzResource -ResourceGroupName "M365-Resources"
    
    $HealthReport = @{
        Timestamp = Get-Date
        Resources = @()
        Issues = @()
    }
    
    foreach ($Resource in $Resources) {
        $ResourceInfo = @{
            Name = $Resource.Name
            Type = $Resource.ResourceType
            Location = $Resource.Location
            Status = "Healthy"
        }
        
        # Check resource health
        try {
            $HealthStatus = Get-AzResourceHealth -ResourceId $Resource.ResourceId
            $ResourceInfo.Status = $HealthStatus.Status
        }
        catch {
            $ResourceInfo.Status = "Unknown"
        }
        
        $HealthReport.Resources += $ResourceInfo
        
        if ($ResourceInfo.Status -ne "Healthy") {
            $HealthReport.Issues += $ResourceInfo
        }
    }
    
    return $HealthReport
}
```

## Best Practices

### Cost Optimization
1. Use Azure Cost Management and Billing
2. Implement resource tagging
3. Regular cost reviews and optimization
4. Use reserved instances for predictable workloads

### Security
1. Enable Azure Security Center
2. Use Azure Key Vault for secrets
3. Implement network security groups
4. Regular security assessments

### Monitoring
1. Set up comprehensive monitoring
2. Create meaningful alerts
3. Regular performance reviews
4. Implement automated responses

### Disaster Recovery
1. Implement backup strategies
2. Test disaster recovery procedures
3. Document recovery processes
4. Regular DR testing

---

*This guide covers Azure integration with M365. For advanced scenarios and specific service configurations, refer to the Azure documentation and service-specific guides.*
