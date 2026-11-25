#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Bundle,
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$BundleSHA256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory)][uri]$TimestampUrl,
    [string]$SignTool = 'signtool.exe'
)
$ErrorActionPreference = 'Stop'
$Output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if ($TimestampUrl.Scheme -notin 'https','http') { throw 'Expected an RFC 3161 timestamp URL' }
if ((Get-FileHash -LiteralPath $Bundle).Hash -ne $BundleSHA256) { throw 'Download digest mismatch' }
if (Test-Path -LiteralPath $Output) { throw 'Choose a new output filename' }
$cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint"
$temp = New-TemporaryFile
$work = [IO.Directory]::CreateDirectory("$($temp.FullName).bundle").FullName
$pending = "$Output.$([guid]::NewGuid()).tmp"
try {
    $zip = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Bundle).Path)
    try {
        $entry = $zip.GetEntry('manifest.json')
        if (!$entry -or $entry.Length -gt 8MB) { throw 'Invalid manifest' }
        $manifestPath = Join-Path $work 'manifest.json'
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$manifestPath)
        $m = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        if ($m.schema -ne 1 -or $m.certificate -ne $cert.GetCertHashString('SHA256')) { throw 'Wrong publisher or bundle format' }
        $files = @($m.files)
        if (!$files.Count -or $zip.Entries.Count -ne 1 + $files.Count) { throw 'Incomplete bundle' }
        foreach ($f in $files) {
            $parts = $f.path -split '/'
            foreach ($part in $parts) {
                if (!$part -or $part -match '[<>:"\\|?*\x00-\x1f]|[. ]$|^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(\.|$)') { throw 'Invalid relative path' }
            }
            $dest = [IO.Path]::Combine($work,$f.path)
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest))
            [IO.Compression.ZipFileExtensions]::ExtractToFile($zip.GetEntry($f.path),$dest)
            if ((Get-FileHash -LiteralPath $dest).Hash -ne $f.sha256) { throw "Unexpected input: $($f.path)" }
        }
    } finally { $zip.Dispose() }
    Write-Host "Build $($m.build), phase $($m.phase), publisher $($cert.Subject)"
    $files | Select-Object path,role,sha256 | Format-Table -AutoSize | Out-Host
    if ((Read-Host 'Type SIGN to sign these files') -cne 'SIGN') { throw 'Cancelled' }
    foreach ($f in $files) {
        $dest = Join-Path $work $f.path
        & $SignTool sign /sha1 $Thumbprint /fd SHA256 /tr $TimestampUrl.AbsoluteUri /td SHA256 $dest
        if ($LASTEXITCODE -ne 0) { throw "Signing failed: $($f.path)" }
        & $SignTool verify /pa /all /tw $dest
        if ($LASTEXITCODE -ne 0) { throw "Verification failed: $($f.path)" }
    }
    [IO.Compression.ZipFile]::CreateFromDirectory($work,$pending)
    [IO.File]::Move($pending,$Output)
    Write-Output (Get-FileHash -LiteralPath $Output)
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
    Remove-Item -LiteralPath $temp.FullName -Force
    if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending -Force }
}
