Clear-Host
$Host.UI.RawUI.WindowTitle = "CPadUnlocker 2. Flash images"
$ErrorActionPreference = "SilentlyContinue"

Set-Location -Path .\unlocker

Write-Output "チャレンジパッド３をシャットダウンした状態で､`r`n本体の音量＋ボタンを押しながらUSBで接続してください｡`r`n"
Start-Sleep -Seconds 2

Clear-Host
python.exe .\mtk script .\flash_boot.txt
Set-Location -Path ..\

Clear-Host
Write-Output "magisk.imgをフラッシュしました｡`r`nUSBを切断後､ 通常通り電源ボタンを長押しして起動してください"
Read-Host "Enter キーを押して終了"
exit 0