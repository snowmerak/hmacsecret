param(
    [ValidateSet("arm64", "amd64")]
    [string]$Architecture = "arm64",
    [string]$Package = "./cmd/hmac-secret",
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($Output)) {
    $Output = Join-Path $projectRoot "hmac-secret.exe"
}
elseif (-not [IO.Path]::IsPathRooted($Output)) {
    $Output = Join-Path $projectRoot $Output
}
$Output = [IO.Path]::GetFullPath($Output)
$outputDirectory = Split-Path -Parent $Output
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
}

Push-Location $projectRoot
try {
    $env:CGO_ENABLED = "0"
    $env:GOOS = "windows"
    $env:GOARCH = $Architecture

    go build -trimpath -o $Output $Package
    if ($LASTEXITCODE -ne 0) {
        throw "Go 실행 파일 빌드에 실패했습니다"
    }
}
finally {
    Pop-Location
}

Write-Host "빌드 완료: $Output"
Write-Host "대상: windows/$Architecture"
Write-Host "CGO: 비활성화 (MSYS2/Clang/외부 DLL 불필요)"
Write-Host "확인: & '$Output' -list"
