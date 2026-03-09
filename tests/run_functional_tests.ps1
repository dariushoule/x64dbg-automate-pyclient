param(
    [string]$RemoteHost      = "192.168.145.130",
    [int]$ReqRepPort    = 27066,
    [int]$PubSubPort    = 27067
)

$ErrorActionPreference = "Stop"
$ImageName = "x64dbg-automate-functional-test"
$RepoRoot  = (Resolve-Path "$PSScriptRoot/..").Path

Write-Host "Building slim container ..."
docker build -t $ImageName -f "$PSScriptRoot/Dockerfile.functional" $RepoRoot

if ($LASTEXITCODE -ne 0) { throw "Docker build failed" }

Write-Host "Running functional test against ${RemoteHost}:${ReqRepPort}/${PubSubPort} ..."
docker run --rm $ImageName python tests/test_functional_remote.py $RemoteHost $ReqRepPort $PubSubPort

if ($LASTEXITCODE -ne 0) { throw "Functional test failed" }
Write-Host "Done."
