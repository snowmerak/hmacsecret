param(
    [string]$MSYS2Root = "C:\msys64",
    [string]$Libfido2Version = "1.17.0",
    # Default: WebAuthn PRF (windows://hello + Security UI for external keys like T120).
    # Raw HID diagnostic: -WindowsWebAuthnPRF:$false
    [switch]$WindowsWebAuthnPRF = $true
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$clangRoot = Join-Path $MSYS2Root "clangarm64"
$clang = Join-Path $clangRoot "bin\clang.exe"
$pkgConfig = Join-Path $clangRoot "bin\pkg-config.exe"
$nativeRoot = Join-Path $projectRoot ".native\libfido2"
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$buildMode = if ($WindowsWebAuthnPRF) { "winwebauthn-prf" } else { "raw-hid" }
$workRoot = Join-Path $tempBase ("libfido2-$buildMode-" + [guid]::NewGuid().ToString("N"))
$sourceRoot = Join-Path $workRoot "src"
$buildRoot = Join-Path $workRoot "build"

foreach ($required in @($clang, $pkgConfig)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "필수 도구를 찾지 못했습니다: $required"
    }
}

$env:CGO_ENABLED = "1"
$env:CC = $clang
$env:PATH = (Join-Path $clangRoot "bin") + ";" + $env:PATH
$env:PKG_CONFIG_PATH = (Join-Path $clangRoot "lib\pkgconfig")

New-Item -ItemType Directory -Force -Path $workRoot, $nativeRoot | Out-Null

try {
    git clone --depth 1 --branch $Libfido2Version `
        https://github.com/Yubico/libfido2.git $sourceRoot
    if ($LASTEXITCODE -ne 0) {
        throw "libfido2 소스를 내려받지 못했습니다"
    }

    # libfido2 1.17.0의 CMake 설정을 Clang 22/MinGW ARM64에 맞춥니다.
    # 라이브러리 구현은 변경하지 않고 빌드 경고 및 링커 설정만 조정합니다.
    $topCMakePath = Join-Path $sourceRoot "CMakeLists.txt"
    $topCMake = Get-Content -Raw -LiteralPath $topCMakePath
    $topCMake = $topCMake.Replace("`r`n", "`n")
    $topCMake = $topCMake.Replace("`tadd_compile_options(-Werror)`n", "")
    $topCMake = $topCMake.Replace(
        "elseif(NOT MSVC)`n`t# clang/gcc + gnu ld",
        "elseif(NOT MSVC AND NOT MINGW)`n`t# clang/gcc + gnu ld"
    )
    $topCMake = $topCMake.Replace(
        '	    " /def:\"${CMAKE_CURRENT_SOURCE_DIR}/src/export.msvc\"")',
        '	    " -Wl,--export-all-symbols")'
    )
    if ($WindowsWebAuthnPRF) {
        $topCMake = $topCMake.Replace(
            "`t`tadd_definitions(-DFIDO_NO_DIAGNOSTIC)`n",
            ""
        )
    }
    Set-Content -LiteralPath $topCMakePath -Value $topCMake -NoNewline

    $srcCMakePath = Join-Path $sourceRoot "src\CMakeLists.txt"
    $srcCMake = Get-Content -Raw -LiteralPath $srcCMakePath
    $srcCMake = $srcCMake.Replace("`r`n", "`n")
    $srcCMake = $srcCMake.Replace(
        "`tlist(APPEND BASE_LIBRARIES wsock32 ws2_32 bcrypt setupapi hid)",
        "`tlist(APPEND BASE_LIBRARIES wsock32 ws2_32 bcrypt setupapi hid)`n`tif(MINGW)`n`t`tlist(APPEND BASE_LIBRARIES winpthread)`n`tendif()"
    )
    Set-Content -LiteralPath $srcCMakePath -Value $srcCMake -NoNewline

    if ($WindowsWebAuthnPRF) {
        # Windows WebAuthn에서 non-discoverable hmac-secret을 PRF 요청으로
        # 변환하고, 내장 Windows Hello 대신 외부 보안 키만 선택하게 합니다.
        $webauthnHeaderPath = Join-Path $sourceRoot "src\webauthn.h"
        $webauthnHeader = Get-Content -Raw -LiteralPath $webauthnHeaderPath
        $webauthnHeader = $webauthnHeader.Replace(
            "WebAuthNGetApiVersionNumber();",
            "WebAuthNGetApiVersionNumber(void);"
        )
        Set-Content -LiteralPath $webauthnHeaderPath -Value $webauthnHeader -NoNewline

        $logPath = Join-Path $sourceRoot "src\log.c"
        $logSource = (Get-Content -Raw -LiteralPath $logPath).Replace("`r`n", "`n")
        $logSource = $logSource.Replace(
            "if (strerror_r(errnum, errstr, sizeof(errstr)) != 0)",
            "if (strerror_s(errstr, sizeof(errstr), errnum) != 0)"
        )
        Set-Content -LiteralPath $logPath -Value $logSource -NoNewline

        $winhelloPath = Join-Path $sourceRoot "src\winhello.c"
        $winhello = (Get-Content -Raw -LiteralPath $winhelloPath).Replace("`r`n", "`n")
        $hmacAnchor = @'
	if (in->attr.mask & FIDO_EXT_HMAC_SECRET) {
		/*
		 * NOTE: webauthn.dll ignores requests to enable hmac-secret
'@
        $hmacReplacement = @'
	if (in->attr.mask & FIDO_EXT_HMAC_SECRET) {
		/*
		 * Map CTAP hmac-secret to the WebAuthn PRF extension. Unlike the
		 * legacy hmac-secret boolean below, PRF works with a
		 * non-discoverable cross-platform credential.
		 */
		opt->bEnablePrf = true;
		if (opt->dwVersion <
		    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6)
			opt->dwVersion =
			    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6;
		/*
		 * NOTE: webauthn.dll ignores requests to enable hmac-secret
'@
        if (-not $winhello.Contains($hmacAnchor)) {
            throw "winhello.c에서 hmac-secret 패치 위치를 찾지 못했습니다"
        }
        $winhello = $winhello.Replace($hmacAnchor, $hmacReplacement)

        $timeoutAnchor = '	opt->dwTimeoutMilliseconds = ms < 0 ? MAXMSEC : (DWORD)ms;'
        $timeoutReplacement = @'
	opt->dwTimeoutMilliseconds = ms < 0 ? MAXMSEC : (DWORD)ms;
	opt->dwAuthenticatorAttachment =
	    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
'@
        $timeoutCount = ([regex]::Matches(
            $winhello,
            [regex]::Escape($timeoutAnchor)
        )).Count
        if ($timeoutCount -ne 2) {
            throw "winhello.c의 authenticator attachment 패치 위치가 2개가 아닙니다: $timeoutCount"
        }
        $winhello = $winhello.Replace($timeoutAnchor, $timeoutReplacement)
        Set-Content -LiteralPath $winhelloPath -Value $winhello -NoNewline
    }

    $nativeUnix = $nativeRoot.Replace("\", "/")
    $useWinHello = if ($WindowsWebAuthnPRF) { "ON" } else { "OFF" }
    $useHIDAPI = if ($WindowsWebAuthnPRF) { "OFF" } else { "ON" }
    cmake -S $sourceRoot -B $buildRoot -G Ninja `
        -DCMAKE_BUILD_TYPE=Release `
        "-DCMAKE_C_COMPILER=$($clang.Replace('\', '/'))" `
        "-DCMAKE_INSTALL_PREFIX=$nativeUnix" `
        -DCMAKE_C_FLAGS=-Wno-tautological-constant-out-of-range-compare `
        -DHAVE_CLOCK_GETTIME=1 `
        "-DUSE_WINHELLO=$useWinHello" `
        "-DUSE_HIDAPI=$useHIDAPI" `
        -DBUILD_SHARED_LIBS=ON `
        -DBUILD_STATIC_LIBS=OFF `
        -DBUILD_TESTS=OFF `
        -DBUILD_TOOLS=OFF `
        -DBUILD_EXAMPLES=OFF `
        -DBUILD_MANPAGES=OFF
    if ($LASTEXITCODE -ne 0) {
        throw "libfido2 CMake 설정에 실패했습니다"
    }

    cmake --build $buildRoot --config Release
    if ($LASTEXITCODE -ne 0) {
        throw "libfido2 빌드에 실패했습니다"
    }
    cmake --install $buildRoot --config Release
    if ($LASTEXITCODE -ne 0) {
        throw "libfido2 설치에 실패했습니다"
    }

    $env:CGO_CFLAGS = "-I$nativeUnix/include -I$($clangRoot.Replace('\', '/'))/include"
    $env:CGO_LDFLAGS = "-L$nativeUnix/lib -L$($clangRoot.Replace('\', '/'))/lib"

    Push-Location $projectRoot
    try {
        go build -a -o .\hmac-secret.exe ./cmd/hmac-secret
        if ($LASTEXITCODE -ne 0) {
            throw "Go 실행 파일 빌드에 실패했습니다"
        }
    }
    finally {
        Pop-Location
    }

    $runtimeDLLs = @(
        (Join-Path $nativeRoot "bin\libfido2.dll"),
        (Join-Path $clangRoot "bin\libcbor.dll"),
        (Join-Path $clangRoot "bin\libcrypto-3-arm64.dll"),
        (Join-Path $clangRoot "bin\libwinpthread-1.dll"),
        (Join-Path $clangRoot "bin\zlib1.dll")
    )
    if (-not $WindowsWebAuthnPRF) {
        $runtimeDLLs += (Join-Path $clangRoot "bin\libhidapi-0.dll")
    }
    foreach ($dll in $runtimeDLLs) {
        Copy-Item -Force -LiteralPath $dll -Destination $projectRoot
    }
    if ($WindowsWebAuthnPRF) {
        $staleHIDAPIDLL = Join-Path $projectRoot "libhidapi-0.dll"
        if (Test-Path -LiteralPath $staleHIDAPIDLL) {
            Remove-Item -Force -LiteralPath $staleHIDAPIDLL
        }
    }

    Write-Host "빌드 완료: $(Join-Path $projectRoot 'hmac-secret.exe')"
    if ($WindowsWebAuthnPRF) {
        Write-Host "Windows WebAuthn PRF 확인: .\hmac-secret.exe -list  (create/assert opens Security UI for T120)"
    }
    else {
        Write-Host "Raw HID 장비 확인: .\hmac-secret.exe -list"
    }
}
finally {
    $resolvedWork = [IO.Path]::GetFullPath($workRoot)
    if ($resolvedWork.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedWork)) {
        Remove-Item -Recurse -Force -LiteralPath $resolvedWork
    }
}
