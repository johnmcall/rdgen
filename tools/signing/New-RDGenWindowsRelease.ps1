#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Kit,
    [Parameter(Mandatory)][string]$Profile,
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][string]$Repository,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Revision,
    [Parameter(Mandatory)][ValidateRange(1,[long]::MaxValue)][long]$RunId,
    [ValidateRange(1,[int]::MaxValue)][int]$Attempt = 1,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$CertificateSha256,
    [Parameter(Mandatory)][uri]$TimestampUrl
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'This release requires Windows x64.' }
if (!(Test-Path -LiteralPath $Kit -PathType Leaf) -or !(Test-Path -LiteralPath $Profile -PathType Leaf)) {
    throw 'Select an Actions artifact ZIP and an RDGen JSON profile.'
}
if (Test-Path -LiteralPath $Output) { throw 'Select a new output directory.' }
if ($TimestampUrl.Scheme -notin 'https','http') { throw 'Expected an RFC 3161 timestamp URL.' }
foreach ($name in 'python','gh','msbuild','pwsh') { Get-Command $name -CommandType Application -ErrorAction Stop | Out-Null }
& python -c 'import sys, PIL, pefile, brotli, asn1crypto, olefile; sys.exit(0 if sys.version_info >= (3,11) and sys.maxsize > 2**32 else 1)'
if ($LASTEXITCODE -ne 0) { throw 'Install 64-bit Python 3.11+ and the dependencies listed in the Windows release guide.' }
$signTool = Get-Command signtool.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (!$signTool) {
    $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
    $signTool = Get-ChildItem "$sdk/*/x64/signtool.exe" | Sort-Object { [version]$_.Directory.Parent.Name } -Descending | Select-Object -First 1
}
if (!$signTool) { throw 'Windows SDK SignTool is required.' }
$toolPath = if ($signTool.Path) { $signTool.Path } else { $signTool.FullName }
$cert = @(Get-ChildItem Cert:/CurrentUser/My -CodeSigningCert | Where-Object {
    $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and $_.NotBefore -le (Get-Date) -and
    $_.GetCertHashString('SHA256') -eq $CertificateSha256
})
if ($cert.Count -ne 1) { throw 'Expected one valid code-signing certificate for this card and publisher fingerprint.' }
$previous = $env:RDGEN_SIGNTOOL
try {
    $env:RDGEN_SIGNTOOL = $toolPath
    & python "$PSScriptRoot/local_release.py" --kit $Kit --profile $Profile --output $Output --repository $Repository --revision $Revision --run $RunId --attempt $Attempt --certificate $CertificateSha256.ToUpperInvariant() --thumbprint $cert[0].Thumbprint --timestamp $TimestampUrl.AbsoluteUri --signtool $toolPath
    if ($LASTEXITCODE -ne 0) { throw 'Local release failed. See the preceding verification result.' }
} finally {
    $env:RDGEN_SIGNTOOL = $previous
}
