# 拉上游新版本并把 local.3 变基上去，重装并验证
# 用法: powershell -ExecutionPolicy Bypass -File ops\upgrade_upstream.ps1 [-Ref origin/master]
param([string]$Ref = "origin/master")
$ErrorActionPreference = "Stop"
$py = "C:\Python314\python.exe"
Set-Location "D:\od\x64dbg-automate-fork"

Write-Host "[1/5] fetch $Ref"
git fetch origin
$stamp = Get-Date -Format "yyyyMMdd-HHmm"
$newBranch = "local.3+$stamp"

Write-Host "[2/5] 建分支 $newBranch 并变基"
git checkout -b $newBranch $Ref
git rebase local.3
if ($LASTEXITCODE -ne 0) {
  Write-Host ""
  Write-Host "变基冲突。解决后执行: git rebase --continue" -ForegroundColor Yellow
  Write-Host "预计冲突点: mcp_server.py (_parse_address_or_expression / toggle_breakpoint / wait_for_event), hla_xauto.py (pause)"
  git status --short
  exit 1
}

Write-Host "[3/5] 重装（editable, 不联网）"
& $py -m pip install -e . --no-build-isolation --no-deps

Write-Host "[4/5] 更新分支指针"
git branch -f local.3 $newBranch
git checkout local.3

Write-Host "[5/5] 验证"
& $py "C:\Users\debugx86\WorkBuddy\2026-11-14-12-15-34\fork_verify.py"
Write-Host "完成。若验证失败: git checkout local.3@{1} 然后重装。" -ForegroundColor Yellow
