# Run on a disposable Windows runner with Pester 5 and the Windows SDK.
Describe 'Windows signing trust checks' {
    BeforeAll {
        $tool = Get-ChildItem "${env:ProgramFiles(x86)}/Windows Kits/10/bin/*/x64/signtool.exe" |
            Sort-Object { [version]$_.Directory.Parent.Name } -Descending | Select-Object -First 1
        $env:RDGEN_SIGNTOOL = $tool.FullName
        $script:inspect = Join-Path $PSScriptRoot '../../tools/signing/Inspect-Signature.ps1'
        $script:cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=RDGen disposable $([guid]::NewGuid())" -CertStoreLocation Cert:\CurrentUser\My
        $script:fingerprint = $cert.GetCertHashString('SHA256')
        $public = Export-Certificate -Cert $cert -FilePath "$TestDrive/publisher.cer"
        Import-Certificate -CertStoreLocation Cert:\CurrentUser\Root -FilePath $public.FullName | Out-Null
        $source = Join-Path $TestDrive 'fixture.cs'
        Set-Content $source 'class Sample { public static int Main() { return 0; } }'
        $script:exe = Join-Path $TestDrive 'fixture.exe'
        & "$env:SystemRoot/Microsoft.NET/Framework64/v4.0.30319/csc.exe" /nologo "/out:$exe" $source
        if ($LASTEXITCODE) { throw 'Cannot build the test fixture' }
    }
    AfterAll {
        if ($cert) {
            Remove-Item -LiteralPath "Cert:\CurrentUser\Root\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey
        }
    }
    It 'rejects an otherwise trusted signature without a timestamp' {
        $target = Join-Path $TestDrive 'untimed.exe'
        Copy-Item $exe $target
        & $env:RDGEN_SIGNTOOL sign /sha1 $cert.Thumbprint /fd SHA256 $target
        $LASTEXITCODE | Should -Be 0
        { & $inspect -File $target -Publisher $fingerprint } | Should -Throw
    }
    It 'accepts the registered publisher and rejects a different fingerprint' -Skip:(!$env:RDGEN_TEST_TIMESTAMP_URL) {
        $target = Join-Path $TestDrive 'timed.exe'
        Copy-Item $exe $target
        & $env:RDGEN_SIGNTOOL sign /sha1 $cert.Thumbprint /fd SHA256 /tr $env:RDGEN_TEST_TIMESTAMP_URL /td SHA256 $target
        $LASTEXITCODE | Should -Be 0
        { & $inspect -File $target -Publisher $fingerprint } | Should -Not -Throw
        { & $inspect -File $target -Publisher ('0' * 64) } | Should -Throw
    }
}
