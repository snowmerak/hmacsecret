param(
    [string]$Package = "./cmd/hmac-secret",
    [string]$Output = ""
)

$buildScript = Join-Path $PSScriptRoot "build-windows.ps1"
& $buildScript `
    -Architecture amd64 `
    -Package $Package `
    -Output $Output
exit $LASTEXITCODE
