param(
    [string]$RemoteHost,
    [int]$ReqRepPort,
    [int]$PubSubPort
)

$ErrorActionPreference = "Stop"
$ImageName = "x64dbg-automate-functional-test"
$RepoRoot  = (Resolve-Path "$PSScriptRoot/..").Path

# Unset parameters fall back to env vars, then tests/local.env (gitignored), then default ports.
$LocalEnv = @{}
$LocalEnvFile = Join-Path $PSScriptRoot "local.env"
if (Test-Path $LocalEnvFile) {
    foreach ($line in Get-Content $LocalEnvFile) {
        $line = $line.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $key, $value = $line.Split("=", 2)
            $LocalEnv[$key.Trim()] = $value.Trim().Trim('"', "'")
        }
    }
}
function Get-Setting([string]$Name, [string]$Default) {
    $fromEnv = [Environment]::GetEnvironmentVariable($Name)
    if ($fromEnv) { return $fromEnv }
    if ($LocalEnv.ContainsKey($Name) -and $LocalEnv[$Name]) { return $LocalEnv[$Name] }
    return $Default
}

if (-not $RemoteHost) { $RemoteHost = Get-Setting "REMOTE_HOST" "" }
if (-not $ReqRepPort) { $ReqRepPort = [int](Get-Setting "REMOTE_REQ_PORT" "27066") }
if (-not $PubSubPort) { $PubSubPort = [int](Get-Setting "REMOTE_PUB_PORT" "27067") }
if (-not $RemoteHost) {
    throw "No remote host: pass -RemoteHost, set REMOTE_HOST, or add it to tests/local.env (see tests/local.env.example)"
}

Write-Host "Building slim container ..."
docker build -t $ImageName -f "$PSScriptRoot/Dockerfile.functional" $RepoRoot

if ($LASTEXITCODE -ne 0) { throw "Docker build failed" }

Write-Host "Running functional test against ${RemoteHost}:${ReqRepPort}/${PubSubPort} ..."
docker run --rm $ImageName python tests/test_functional_remote.py $RemoteHost $ReqRepPort $PubSubPort

if ($LASTEXITCODE -ne 0) { throw "Functional test failed" }
Write-Host "Done."
