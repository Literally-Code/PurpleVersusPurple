
#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
Creates and links additive AD security GPOs, including a domain-wide
RDP restriction, without modifying default GPOs.

.DESCRIPTION
Configures:
- Domain password and account lockout policies
- LDAP signing requirements for domain controllers
- SMB signing requirements for domain controllers
- PowerShell script block logging on domain controllers
- Audit-related registry settings on domain controllers
- Domain-wide disabling of incoming Remote Desktop connections

.EXAMPLE
.\Harden-ADPolicies.ps1

Preview planned changes without applying them.

.EXAMPLE
.\Harden-ADPolicies.ps1 -Apply

Apply the security baseline after confirmation.

.NOTES
Run in an elevated Windows PowerShell session with authorized
Active Directory and Group Policy administration rights.

Test compatibility before deploying LDAP/SMB signing requirements.

WARNING:
Disabling RDP domain-wide can prevent remote administration.
Ensure console or alternative administrative access is available.

Advanced audit subcategories are not automatically configured.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [string]$BackupPath = 'C:\GPO-Backups',
    [int]$MinimumPasswordLength = 14,
    [int]$LockoutThreshold = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory
Import-Module GroupPolicy

# ------------------------------------------------------------
# Domain information
# ------------------------------------------------------------

$domain = Get-ADDomain
$dn = $domain.DistinguishedName
$dcOu = "OU=Domain Controllers,$dn"

# ------------------------------------------------------------
# GPO names
# ------------------------------------------------------------

$domainGpoName = 'Security Baseline - Domain Accounts'
$dcGpoName = 'Security Baseline - Domain Controllers'
$rdpGpoName = 'Security Baseline - Disable RDP'

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------

function Set-RegistryPolicyValue {
    param(
        [string]$Gpo,
        [string]$Key,
        [string]$Name,
        [string]$Type,
        [object]$Value
    )

    Set-GPRegistryValue `
        -Name $Gpo `
        -Key $Key `
        -ValueName $Name `
        -Type $Type `
        -Value $Value | Out-Null
}

function Ensure-Gpo {
    param(
        [string]$Name,
        [string]$Target
    )

    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue

    if (-not $gpo) {
        $gpo = New-GPO `
            -Name $Name `
            -Comment 'Additive security baseline; validate against Microsoft security baselines.'
    }

    $links = (Get-GPInheritance -Target $Target).GpoLinks

    if (-not ($links | Where-Object { $_.DisplayName -eq $Name })) {
        New-GPLink `
            -Name $Name `
            -Target $Target `
            -LinkEnabled Yes | Out-Null
    }
}

# ------------------------------------------------------------
# Preview configuration
# ------------------------------------------------------------

Write-Host ""
Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Cyan
Write-Host "Domain Controllers OU: $dcOu"

Write-Host ""
Write-Host 'Planned configuration:' -ForegroundColor Yellow

Write-Host "  Domain account password length >= $MinimumPasswordLength"
Write-Host "  Domain account lockout threshold: $LockoutThreshold"

Write-Host '  DC: require LDAP signing'
Write-Host '  DC: require SMB signing'
Write-Host '  DC: enable PowerShell script block logging'
Write-Host '  DC: enable audit-related registry settings'

Write-Host '  Domain-wide: disable incoming Remote Desktop connections'

Write-Host '  Existing default GPOs are backed up, not edited.'

Write-Host ""

# ------------------------------------------------------------
# Preview-only mode
# ------------------------------------------------------------

if (-not $Apply) {
    Write-Warning 'PREVIEW ONLY: No changes made. Rerun with -Apply to make changes.'
    return
}

# ------------------------------------------------------------
# Parameter validation
# ------------------------------------------------------------

if ($MinimumPasswordLength -lt 14 -or $MinimumPasswordLength -gt 20) {
    throw 'MinimumPasswordLength must be between 14 and 20.'
}

if ($LockoutThreshold -lt 1 -or $LockoutThreshold -gt 20) {
    throw 'LockoutThreshold must be between 1 and 20.'
}

# ------------------------------------------------------------
# Apply security policies
# ------------------------------------------------------------

$operation = 'Back up default GPOs, configure domain account policy, create security baseline GPOs, and disable incoming RDP domain-wide'

if ($PSCmdlet.ShouldProcess($domain.DNSRoot, $operation)) {

    # --------------------------------------------------------
    # Back up default GPOs
    # --------------------------------------------------------

    Write-Host 'Backing up default GPOs...' -ForegroundColor Cyan

    New-Item `
        -ItemType Directory `
        -Path $BackupPath `
        -Force | Out-Null

    foreach ($name in @(
        'Default Domain Policy',
        'Default Domain Controllers Policy'
    )) {
        Backup-GPO `
            -Name $name `
            -Path $BackupPath `
            -Comment "Pre-hardening backup $(Get-Date -Format o)" |
            Out-Null
    }

    # --------------------------------------------------------
    # Domain password policy
    # --------------------------------------------------------

    Write-Host 'Configuring domain password policy...' -ForegroundColor Cyan

    Set-ADDefaultDomainPasswordPolicy `
        -Identity $domain.DNSRoot `
        -MinPasswordLength $MinimumPasswordLength `
        -ComplexityEnabled $true `
        -PasswordHistoryCount 24 `
        -MinPasswordAge (New-TimeSpan -Days 1) `
        -MaxPasswordAge (New-TimeSpan -Days 365) `
        -LockoutThreshold $LockoutThreshold `
        -LockoutDuration (New-TimeSpan -Minutes 15) `
        -LockoutObservationWindow (New-TimeSpan -Minutes 15)

    # --------------------------------------------------------
    # Create and link baseline GPOs
    # --------------------------------------------------------

    Write-Host 'Creating and linking security baseline GPOs...' -ForegroundColor Cyan

    # Domain account baseline placeholder.
    # Password policy is configured using AD cmdlets above.
    Ensure-Gpo `
        -Name $domainGpoName `
        -Target $dn

    # Domain controller baseline.
    Ensure-Gpo `
        -Name $dcGpoName `
        -Target $dcOu

    # Domain-wide Remote Desktop restriction.
    Ensure-Gpo `
        -Name $rdpGpoName `
        -Target $dn

    # --------------------------------------------------------
    # Domain controller: LDAP signing
    # --------------------------------------------------------

    Write-Host 'Configuring LDAP signing...' -ForegroundColor Cyan

    # LDAPServerIntegrity:
    # 2 = Require signing

    Set-RegistryPolicyValue `
        -Gpo $dcGpoName `
        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
        -Name 'LDAPServerIntegrity' `
        -Type DWord `
        -Value 2

    # --------------------------------------------------------
    # Domain controller: SMB signing
    # --------------------------------------------------------

    Write-Host 'Configuring SMB signing...' -ForegroundColor Cyan

    # Require SMB signing on the server side.

    Set-RegistryPolicyValue `
        -Gpo $dcGpoName `
        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'RequireSecuritySignature' `
        -Type DWord `
        -Value 1

    # Require SMB signing on the client side.

    Set-RegistryPolicyValue `
        -Gpo $dcGpoName `
        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
        -Name 'RequireSecuritySignature' `
        -Type DWord `
        -Value 1

    # --------------------------------------------------------
    # Domain controller: PowerShell logging
    # --------------------------------------------------------

    Write-Host 'Configuring PowerShell logging...' -ForegroundColor Cyan

    Set-RegistryPolicyValue `
        -Gpo $dcGpoName `
        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name 'EnableScriptBlockLogging' `
        -Type DWord `
        -Value 1

    # --------------------------------------------------------
    # Domain controller: Audit-related settings
    # --------------------------------------------------------

    Write-Host 'Configuring audit-related settings...' -ForegroundColor Cyan

    # Include command-line arguments in process creation events.
    # Requires process creation auditing to be enabled separately.

    Set-RegistryPolicyValue `
        -Gpo $dcGpoName `
        -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' `
        -Type DWord `
        -Value 1

    # Advanced audit policy overrides legacy audit policy.

    Set-RegistryPolicyValue `
        -Gpo $dcGpoName `
        -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'SCENoApplyLegacyAuditPolicy' `
        -Type DWord `
        -Value 1

    # --------------------------------------------------------
    # Domain-wide: Disable Remote Desktop
    # --------------------------------------------------------

    Write-Host 'Configuring domain-wide RDP restriction...' -ForegroundColor Cyan

    # Disable incoming Remote Desktop connections.
    #
    # Group Policy location:
    # Computer Configuration
    #   Administrative Templates
    #     Windows Components
    #       Remote Desktop Services
    #         Remote Desktop Session Host
    #           Connections
    #
    # Allow users to connect remotely by using
    # Remote Desktop Services = Disabled
    #
    # fDenyTSConnections:
    # 1 = Deny incoming RDP connections
    # 0 = Allow incoming RDP connections

    Set-RegistryPolicyValue `
        -Gpo $rdpGpoName `
        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
        -Name 'fDenyTSConnections' `
        -Type DWord `
        -Value 1

    # --------------------------------------------------------
    # Completion
    # --------------------------------------------------------

    Write-Host ""
    Write-Host 'Security baseline configuration completed.' -ForegroundColor Green

    Write-Host ""
    Write-Host 'Configured GPOs:' -ForegroundColor Cyan
    Write-Host "  $domainGpoName"
    Write-Host "  $dcGpoName"
    Write-Host "  $rdpGpoName"

    Write-Host ""
    Write-Host "Backups: $BackupPath"

    Write-Host ""
    Write-Warning 'Advanced audit subcategories are NOT automatically configured.'
    Write-Warning 'Configure audit subcategories through GPMC Advanced Audit Policy Configuration.'
    Write-Warning 'Review LDAP clients and SMB compatibility before policy refresh.'
    Write-Warning 'LDAP channel binding is not changed.'
    Write-Warning 'RDP will be disabled on applicable domain-joined Windows computers after Group Policy refresh.'
    Write-Warning 'Ensure alternative administrative access is available.'

    Write-Host ""
    Write-Host 'Validation commands:' -ForegroundColor Yellow
    Write-Host '  gpupdate /force'
    Write-Host '  gpresult /scope computer /r'
    Write-Host '  Get-ADDefaultDomainPasswordPolicy'

    Write-Host ""
    Write-Host 'Check RDP policy on a domain-joined computer:'
    Write-Host "  Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDenyTSConnections"
}
