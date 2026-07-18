# 从手机拉取扫描结果到本机
param(
    [string]$Out = "D:\grok-cli\workspace\jcc-device-scan\out\from-phone"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
Write-Host "pull /sdcard/Download/jcc-scan -> $Out"
adb pull /sdcard/Download/jcc-scan $Out
if (Test-Path (Join-Path $Out "jcc-scan\DONE")) {
    Write-Host "OK: DONE found"
} elseif (Test-Path (Join-Path $Out "DONE")) {
    Write-Host "OK: DONE found"
} else {
    Write-Host "WARN: DONE not found, check status.txt"
}
Get-ChildItem $Out -Recurse -File | Select-Object FullName, Length
