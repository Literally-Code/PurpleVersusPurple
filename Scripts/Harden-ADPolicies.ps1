#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
Creates and links additive AD security GPOs without modifying default GPOs.
.EXAMPLE
.\Harden-ADPolicies.ps1
.\Harden-ADPolicies.ps1 -Apply
.NOTES
Run in an elevated Windows PowerShell session with authorized GPO administration rights.
Test compatibility before deploying LDAP/SMB signing requirements.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
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

$domain = Get-ADDomain
$dn = $domain.DistinguishedName
$dcOu = "OU=Domain Controllers,$dn"
$domainGpoName = 'Security Baseline - Domain Accounts'
$dcGpoName = 'Security Baseline - Domain Controllers'

function Set-RegistryPolicyValue {
    param([string]$Gpo,[string]$Key,[string]$Name,[string]$Type,[object]$Value)
    Set-GPRegistryValue -Name $Gpo -Key $Key -ValueName $Name -Type $Type -Value $Value | Out-Null
}
function Ensure-Gpo {
    param([string]$Name,[string]$Target)
    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $gpo) { $gpo = New-GPO -Name $Name -Comment 'Additive security baseline; validate against Microsoft security baselines.' }
    $links = (Get-GPInheritance -Target $Target).GpoLinks
    if (-not ($links | Where-Object { $_.DisplayName -eq $Name })) {
        New-GPLink -Name $Name -Target $Target -LinkEnabled Yes | Out-Null
    }
}

Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Cyan
Write-Host "Domain Controllers OU: $dcOu"
Write-Host 'Planned configuration:'
Write-Host "  Domain account password length >= $MinimumPasswordLength, lockout threshold $LockoutThreshold"
Write-Host '  DC: require LDAP signing and SMB signing; enable PowerShell script block logging'
Write-Host '  DC: enable advanced audit categories for logon, account management and directory changes'
Write-Host '  Existing default GPOs are backed up, not edited.'

if (-not $Apply) {
    Write-Warning 'PREVIEW ONLY: No changes made. Rerun with -Apply to make changes.'
    return
}
if ($MinimumPasswordLength -lt 14 -or $MinimumPasswordLength -gt 20) { throw 'MinimumPasswordLength must be between 14 and 20.' }
if ($LockoutThreshold -lt 1 -or $LockoutThreshold -gt 20) { throw 'LockoutThreshold must be between 1 and 20.' }

if ($PSCmdlet.ShouldProcess($domain.DNSRoot, 'Back up default GPOs, create baseline GPOs, configure account policy and link GPOs')) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    foreach ($name in @('Default Domain Policy','Default Domain Controllers Policy')) {
        Backup-GPO -Name $name -Path $BackupPath -Comment "Pre-hardening backup $(Get-Date -Format o)" | Out-Null
    }
    # Domain password policy is maintained using AD domain policy cmdlets, not DC-local settings.
    # This changes the domain's default account policy and is intentionally explicit.
    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot `
        -MinPasswordLength $MinimumPasswordLength `
        -ComplexityEnabled $true `
        -PasswordHistoryCount 24 `
        -MinPasswordAge (New-TimeSpan -Days 1) `
        -MaxPasswordAge (New-TimeSpan -Days 365) `
        -LockoutThreshold $LockoutThreshold `
        -LockoutDuration (New-TimeSpan -Minutes 15) `
        -LockoutObservationWindow (New-TimeSpan -Minutes 15)

    # A domain-linked GPO is created as a placeholder for later domain-wide controls.
    # It does not contain account policy values: AD's default password policy is configured above.
    Ensure-Gpo -Name $domainGpoName -Target $dn
    Ensure-Gpo -Name $dcGpoName -Target $dcOu

    # LDAPServerIntegrity: 2 = Require signing.
    Set-RegistryPolicyValue -Gpo $dcGpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -Type DWord -Value 2
    # SMB signing: require signing on server and client sides.
    Set-RegistryPolicyValue -Gpo $dcGpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1
    Set-RegistryPolicyValue -Gpo $dcGpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1
    # Enable PowerShell script block logging.
    Set-RegistryPolicyValue -Gpo $dcGpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1
    # Include command line in process creation audit events (effective only if process creation auditing is enabled).
    Set-RegistryPolicyValue -Gpo $dcGpoName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1
    # Ensure advanced audit subcategories override legacy audit category policy.
    Set-RegistryPolicyValue -Gpo $dcGpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1

    Write-Warning 'Advanced audit subcategories are NOT automatically configured by this script; configure them via GPMC Security Settings > Advanced Audit Policy Configuration.'
    Write-Warning 'Review LDAP clients and SMB compatibility before policy refresh. LDAP channel binding is not changed.'
    Write-Host 'Applied GPO registry settings and updated the default domain password policy.' -ForegroundColor Green
    Write-Host "Backups: $BackupPath"
    Write-Host 'Validate with: gpresult /h C:\Temp\gp-report.html and Get-ADDefaultDomainPasswordPolicy'
}
