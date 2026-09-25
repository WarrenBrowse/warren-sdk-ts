# Installs the Warren browser extension's helper for the current user on
# Windows. No administrator rights, no runtime: it downloads one executable,
# checks it against the release's SHA256SUMS, and lets it register itself with
# every browser it finds. Windows PowerShell 5.1 or later.
#
#   powershell -ExecutionPolicy Bypass -c "irm https://github.com/WarrenBrowse/warren-sdk-ts/releases/download/__WARREN_HOST_TAG__/install.ps1 | iex"
#
# Everything runs from the function called on the last line, so a download cut
# short installs nothing.

function Install-WarrenHelper {
    param([string[]]$HelperArgs = @())

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    # Windows PowerShell 5.1 still offers TLS 1.0 first; GitHub refuses it.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $tag = '__WARREN_HOST_TAG__'
    $base = "https://github.com/WarrenBrowse/warren-sdk-ts/releases/download/$tag"
    if ($env:WARREN_HELPER_BASE_URL) { $base = $env:WARREN_HELPER_BASE_URL }
    $asset = 'Warren-Helper-Setup.exe'

    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'The Warren helper needs a 64-bit Windows.'
    }
    if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) {
        throw 'Get-FileHash is required to check the download (PowerShell 4 or later).'
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('warren-helper-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $exe = Join-Path $tmp $asset
        $sums = Join-Path $tmp 'SHA256SUMS'
        Write-Host "Downloading the Warren helper ($asset)..."
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $exe
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums

        $expected = $null
        foreach ($line in Get-Content -Path $sums) {
            $parts = $line.Trim() -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $asset) {
                $expected = $parts[0].ToLowerInvariant()
                break
            }
        }
        if (-not $expected) { throw "SHA256SUMS has no entry for $asset." }
        $actual = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash.ToLowerInvariant()
        if ($actual -ne $expected) { throw "Checksum mismatch for ${asset}: refusing to run it." }

        & $exe install @HelperArgs
        if ($LASTEXITCODE -ne 0) { throw "The helper install failed (exit $LASTEXITCODE)." }
    }
    finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }
}

Install-WarrenHelper -HelperArgs $args
