<#
.SYNOPSIS
    Authenticode-sign one Windows file with Azure Trusted Signing (Sweet Papa Technologies).

.DESCRIPTION
    Uses Microsoft's `sign` CLI and the active Azure CLI session (GitHub OIDC in CI,
    `az login` locally). Account details come from metadata.json in the repository root.

    One-time setup on a local machine:
      az login
      dotnet tool install --global sign --prerelease

.EXAMPLE
    pwsh -NoProfile -File scripts/sign-windows.ps1 -Path .\dist\fcsweep.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$Description = 'FoFo Care Sweep'
)

$ErrorActionPreference = 'Stop'
$repoDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$meta = Get-Content (Join-Path $repoDir 'metadata.json') -Raw | ConvertFrom-Json
$file = (Resolve-Path $Path).Path

$sign = Get-Command sign -ErrorAction SilentlyContinue
$signExe = if ($sign) { $sign.Source } else { Join-Path $HOME '.dotnet\tools\sign.exe' }
if (-not (Test-Path $signExe)) {
    throw "the 'sign' tool is not installed: dotnet tool install --global sign --prerelease"
}

$maxAttempts = 3
$lastOut = ''
$signed = $false

for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    Write-Host "[sign-windows] attempt $attempt/$maxAttempts signing $file"
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lastOut = (& $signExe code trusted-signing (Split-Path -Leaf $file) `
        --base-directory (Split-Path -Parent $file) `
        --trusted-signing-endpoint $meta.Endpoint `
        --trusted-signing-account $meta.CodeSigningAccountName `
        --trusted-signing-certificate-profile $meta.CertificateProfileName `
        --description $Description `
        --description-url 'https://github.com/Sweet-Papa-Technologies/FoFo-Sweeper' `
        --timestamp-url 'http://timestamp.acs.microsoft.com' `
        --file-digest SHA256 `
        --verbosity Information 2>&1 | Out-String)
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevPref

    if ($code -eq 0) {
        $signed = $true
        break
    }

    Write-Host "[sign-windows] attempt $attempt failed (exit $code): $lastOut"
    if ($attempt -lt $maxAttempts) {
        Start-Sleep -Seconds 5
    }
}

if (-not $signed) {
    throw "sign exited with $code for $file`n$lastOut"
}

$sig = Get-AuthenticodeSignature $file
Write-Host "[sign-windows] $($sig.Status): $($sig.SignerCertificate.Subject)"
if ($sig.Status -ne 'Valid') {
    throw "signature on $file is $($sig.Status)"
}
