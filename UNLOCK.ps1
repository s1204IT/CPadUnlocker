Clear-Host
$Host.UI.RawUI.WindowTitle = "CPadUnlocker 1. Extract images"
$ErrorActionPreference = "SilentlyContinue"

Set-Location -Path .\unlocker

Write-Output "チャレンジパッド３をシャットダウンした状態で､`r`n本体の音量＋ボタンを押しながらUSBで接続してください｡`r`n"
Start-Sleep -Seconds 2

Clear-Host
Write-Output "`r`nコンソールの出力が停止した場合は`r`nWindows Updateからドライバの更新を確認した後､`r`nPCを再起動してもう一度試してください｡`r`n"
python.exe .\mtk script .\extract_boot.txt
Set-Location -Path ..\

Clear-Host
Write-Output "boot.img を抽出しました｡`r`nMagiskでパッチ後､ ｢magisk.img｣としてコピーしてください｡`r`n`r`nLittle Kernelの修正は任意で行ってください"
Read-Host "Enter キーを押して終了"
exit 0