# 验证 local.3：工具数、A1 别名、A2 drain、xref、算式解析
# 用法: powershell -ExecutionPolicy Bypass -File ops\verify.ps1
$ErrorActionPreference = "Continue"
$py = "C:\Python314\python.exe"
$root = "D:\od\x64dbg-automate-fork"

& $py "$root\ops\verify.py"
$code = $LASTEXITCODE
if ($code -ne 0) {
  Write-Host "verify FAILED (exit=$code)" -ForegroundColor Red
  exit $code
}
Write-Host "verify PASSED" -ForegroundColor Green
