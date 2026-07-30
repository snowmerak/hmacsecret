param(
    [ValidateSet("arm64", "amd64")]
    [string]$Architecture = "arm64",
    [string]$MSYS2Root = "C:\msys64",
    [string]$Package = "./cmd/hmac-secret",
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$environmentName = switch ($Architecture) {
    "arm64" { "clangarm64" }
    "amd64" { "clang64" }
}
$toolchainRoot = Join-Path $MSYS2Root $environmentName
$toolchainBin = Join-Path $toolchainRoot "bin"
$clang = Join-Path $toolchainBin "clang.exe"
$pkgConfig = Join-Path $toolchainBin "pkg-config.exe"

foreach ($required in @($clang, $pkgConfig)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "필수 도구를 찾지 못했습니다: $required"
    }
}

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

$env:CGO_ENABLED = "1"
$env:GOOS = "windows"
$env:GOARCH = $Architecture
$env:CC = $clang
$env:PATH = $toolchainBin + ";" + $env:PATH
$env:PKG_CONFIG_PATH = Join-Path $toolchainRoot "lib\pkgconfig"
Remove-Item Env:CGO_CFLAGS -ErrorAction SilentlyContinue
Remove-Item Env:CGO_LDFLAGS -ErrorAction SilentlyContinue

Push-Location $projectRoot
try {
    go build -o $Output $Package
    if ($LASTEXITCODE -ne 0) {
        throw "Go 실행 파일 빌드에 실패했습니다"
    }
}
finally {
    Pop-Location
}

$runtimeDLLs = @(
    (Join-Path $toolchainBin "libcbor.dll"),
    (Join-Path $toolchainBin "libwinpthread-1.dll"),
    (Join-Path $toolchainBin "zlib1.dll")
)
$cryptoDLLs = @(
    Get-ChildItem -LiteralPath $toolchainBin -Filter "libcrypto-3-*.dll" |
        Select-Object -ExpandProperty FullName
)
if ($cryptoDLLs.Count -ne 1) {
    throw "OpenSSL 런타임 DLL을 하나로 결정할 수 없습니다: $toolchainBin\libcrypto-3-*.dll"
}
$runtimeDLLs += $cryptoDLLs[0]

foreach ($dll in $runtimeDLLs) {
    if (-not (Test-Path -LiteralPath $dll)) {
        throw "런타임 DLL을 찾지 못했습니다: $dll"
    }
    Copy-Item -Force -LiteralPath $dll -Destination $outputDirectory
}

Write-Host "빌드 완료: $Output"
Write-Host "대상: windows/$Architecture"
Write-Host "libfido2: cgo에 정적 포함됨"
Write-Host "확인: & '$Output' -list"
