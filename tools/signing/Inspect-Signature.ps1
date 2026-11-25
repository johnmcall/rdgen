param([Parameter(Mandatory)][string]$File, [string]$Publisher, [switch]$Classify)
$ErrorActionPreference = 'Stop'
$sig = Get-AuthenticodeSignature -LiteralPath $File
if ($Classify) {
    if ($sig.Status -eq 'NotSigned') { 'unsigned'; exit 0 }
    if ($sig.Status -ne 'Valid') { throw "Untrusted signature in $File" }
    $sig.SignerCertificate.GetCertHashString('SHA256')
    exit 0
}
if ($sig.Status -ne 'Valid' -or !$sig.TimeStamperCertificate -or
    $sig.SignerCertificate.GetCertHashString('SHA256') -ne $Publisher) {
    throw "Unexpected signer, invalid signature or missing timestamp: $File"
}
& $env:RDGEN_SIGNTOOL verify /pa /all /tw $File | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Windows trust check failed: $File" }
