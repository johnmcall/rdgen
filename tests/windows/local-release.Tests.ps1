Describe 'Local Windows release inputs' {
    BeforeAll {
        $script:entry = Join-Path $PSScriptRoot '../../tools/signing/New-RDGenWindowsRelease.ps1'
    }
    It 'parses on PowerShell 7' {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($entry, [ref]$tokens, [ref]$errors) | Out-Null
        $errors.Count | Should -Be 0
    }
    It 'rejects an existing output before accessing a signing card' -Skip:(!$IsWindows) {
        $kit = New-Item "$TestDrive/kit.zip" -ItemType File
        $json = New-Item "$TestDrive/profile.json" -ItemType File
        { & $entry -Kit $kit.FullName -Profile $json.FullName -Output $TestDrive -Repository example/rdgen -Revision ('1'*40) -RunId 1 -CertificateSha256 ('2'*64) -TimestampUrl https://example.invalid } | Should -Throw '*new output directory*'
    }
}
