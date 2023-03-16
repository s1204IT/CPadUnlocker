Clear-Host
$Host.UI.RawUI.WindowTitle = "Installing CPadUnlocker..."
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

if ($(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6D4A6ED0-CF41-4615-A4B3-BDA018C3C1CD}\') -ne $true) {
    Write-Output "UsbDk をセットアップしています..."
    Invoke-WebRequest -Uri "https://github.com/daynix/UsbDk/releases/download/v1.00-22/UsbDk_1.0.22_x64.msi" -OutFile .\UsbDk.msi -UseBasicParsing
    Start-Process -NoNewWindow -FilePath msiexec.exe -ArgumentList "/i UsbDk.msi /passive" -WorkingDirectory .\
    Remove-Item -Force .\UsbDk.msi
}
if ($(python.exe .\test.py) -ne "OK!") {
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "ERROR: Failed Python vetify"
    Write-Output "Python 3.8以降がインストールされていません`r`nインストール後､ 再試行してください`r`n"
    Read-Host "Enter キーを押して終了" | Out-Null
    exit 1
}

Write-Output "必要なライブラリをインストールしています..."
pip -q install --upgrade --disable-pip-version-check -r .\unlocker\requirements.txt --no-warn-script-location | Out-Null
if ($? -ne $true) {
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "ERROR: Failed pip install"
    Write-Output "pip の実行に失敗しました。`r`n"
    Read-Host "Enter キーを押して終了" | Out-Null
    exit 1
}

Write-Output "ドライバーをセットアップします..."
Invoke-WebRequest -Uri https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2016/10/20931647_c83f434a6c4ffff12b48edefe161d6085bb63bcd.cab -OutFile .\mtk.cab -UseBasicParsing
Invoke-WebRequest -Uri https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2016/08/20913465_17e56bbd9fe9351b9477154c0414ce86e21a42bb.cab -OutFile .\mtl-port.cab -UseBasicParsing
New-Item .\cab -ItemType Directory -Force | Out-Null
expand.exe mtk.cab -F:* cab | Out-Null
pnputil.exe /add-driver .\cab\android_winusb.inf /install | Out-Null
Remove-Item -Recurse -Force .\cab\*
expand.exe mtk-port.cab -F:* cab | Out-Null
pnputil.exe /add-driver .\cab\*.inf /install | Out-Null
Remove-Item -Recurse -Force .\*.cab,.\cab\

Clear-Host
Write-Output "完了しました！`r`n"
Read-Host "Enter キーを押して再起動"
shutdown.exe /r /f /t 0
exit 0