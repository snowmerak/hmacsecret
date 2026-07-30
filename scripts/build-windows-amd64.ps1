param(
    [string]$MSYS2Root = "C:\msys64",
    [string]$Package = "./cmd/hmac-secret",
    [string]$Output = ""
)

$buildScript = Join-Path $PSScriptRoot "build-windows.ps1"
& $buildScript `
    -Architecture amd64 `
    -MSYS2Root $MSYS2Root `
    -Package $Package `
    -Output $Output
exit $LASTEXITCODE
