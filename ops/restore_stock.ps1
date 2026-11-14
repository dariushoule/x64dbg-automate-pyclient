# 回滚到 pip 官方 0.9.2（含原 p1/p2 补丁状态）
# 用法: powershell -ExecutionPolicy Bypass -File ops\restore_stock.ps1
$ErrorActionPreference = "Stop"
$py = "C:\Python314\python.exe"
$sp = "C:\Python314\Lib\site-packages"
$bk = "D:\toolkit\backup\x64dbg_automate_0.9.2_20261114"

if (-not (Test-Path "$bk\pkg_original")) { throw "备份不存在: $bk\pkg_original" }

Write-Host "[1/4] 卸载 editable 包"
& $py -m pip uninstall -y x64dbg_automate

Write-Host "[2/4] 清理 site-packages 残留"
if (Test-Path "$sp\x64dbg_automate") { Remove-Item -Recurse -Force "$sp\x64dbg_automate" }
Get-ChildItem $sp -Filter "*x64dbg_automate*" | Remove-Item -Recurse -Force
Get-ChildItem $sp -Filter "__editable__*x64dbg*" | Remove-Item -Force

Write-Host "[3/4] 还原备份源码与元数据"
Copy-Item -Recurse -Force "$bk\pkg_original" "$sp\x64dbg_automate"
Copy-Item -Recurse -Force "$bk\dist-info" "$sp\x64dbg_automate-0.9.2.dist-info"

Write-Host "[4/4] 验证"
& $py -c "import importlib.metadata as md, x64dbg_automate as m; print('version:', md.version('x64dbg_automate')); print('path   :', m.__file__)"
Write-Host "已回滚到 0.9.2（p1/p2 猴补丁原状）。注意: 此状态下 xref 仍然漏检、pause 需要外部重试。"
