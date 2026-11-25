# Build a signed Windows client from a neutral kit

GitHub Actions compiles RustDesk 1.5.3 for Windows x64. On your Windows workstation, a PowerShell script applies a connection profile and icon, signs the application files, builds a portable executable and an MSI installer, and signs both packages. You can reuse one kit for several profiles.

## Download the kit

1. In the repository's **Actions** tab, open **Neutral Windows release kit** and choose **Run workflow**. Select version **1.5.3** and architecture **x64**.
2. After the run succeeds, download the original ZIP named `neutral-windows-x64-<run-id>-<attempt>.zip`. Keep the ZIP intact. Record the repository name, full workflow commit SHA, run ID and attempt number.
3. In an RDGen instance running this version, enter a configuration name, ID server host and port, public server key, API URL, optional relay address, and optional square PNG icon. Click **Save Windows Connection Profile** and save the JSON on your workstation. Leaving the relay blank retains the client's usual relay selection.

The workflow currently runs on demand and targets this RustDesk version. The ZIP contains the compiled client, libraries and packaging inputs. Treat the kit and build logs as public when using a public repository.

## Prepare the signing workstation

Use Windows x64 with PowerShell 7.2 or later, 64-bit Python 3.11 or later, GitHub CLI with read access to the workflow run, Visual Studio 2022 Build Tools with MSBuild, and Windows SDK SignTool. The signing certificate must be available in the current user's personal certificate store. For a hardware card, install the vendor's middleware and connect the reader.

Open a Developer PowerShell with MSBuild on the path. Use a trusted checkout of the workflow revision and install the Python dependencies in an active virtual environment.

```powershell
python -m pip install -r tools/signing/requirements-windows-release.txt
```

The first WiX 4.0.5 restore needs access to its NuGet packages. Signature timestamping needs access to the publisher's RFC 3161 service. Have the certificate's public SHA-256 fingerprint available.

## Create the release

Replace the example repository, run ID and paths with those from your build. The output directory must be new and its parent must already exist.

```powershell
$revision = Read-Host 'Full workflow commit SHA'
$publisher = Read-Host 'Public SHA-256 fingerprint of your signing certificate'
$timestamp = Read-Host 'RFC 3161 timestamp service URL'
./tools/signing/New-RDGenWindowsRelease.ps1 `
  -Kit 'C:/RDGen/neutral-windows-x64-12345-1.zip' -Profile 'C:/RDGen/example.json' `
  -Output 'C:/RDGen/releases/example' -Repository 'example/rdgen' `
  -Revision $revision -RunId 12345 -Attempt 1 -CertificateSha256 $publisher -TimestampUrl $timestamp
```

The script checks the ZIP against GitHub's artifact digest and the selected run, applies your profile, and checks the packaging tools. At each signing prompt, review the files and enter the PIN in the card middleware dialog. Once both packages pass verification, the output directory contains **RustDesk.exe**, **RustDesk.msi** and **SHA256.json**. To produce a second profile, select the same original ZIP, the second JSON and a fresh output directory.

Before distributing a new build, verify the portable client and MSI on a clean Windows machine. [Windows release checks](../tests/windows/neutral-release-pilot.md)
