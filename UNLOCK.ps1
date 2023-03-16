Clear-Host
$Host.UI.RawUI.WindowTitle = "CPadUnlocker"
$ErrorActionPreference = "SilentlyContinue"

Set-Location -Path .\unlocker

Write-Output "チャレンジパッド３をシャットダウンした状態で､`r`n本体の音量＋ボタンを押しながらUSBで接続してください｡`r`n"
Start-Sleep -Seconds 1

Clear-Host
$Host.UI.RawUI.WindowTitle = "MTKClient"
Write-Output "`r`nコンソールの出力が停止した場合はPCを再起動してもう一度試してください｡`r`n"
python.exe .\mtk script .\execute | Out-Null
python.exe .\mtk reset

Set-Location -Path ..\