# Phase 0 PoC runner (Windows). Runs score.py inside the framac-pipeline image with the repository
# mounted read-only and results written to poc/phase0/out/.
#
#   .\poc\phase0\run.ps1 reproducers [-Only r01_static_collision,r03_function_pointers]
#   .\poc\phase0\run.ps1 fetch                       # clone benchmark targets (host, needs network)
#   .\poc\phase0\run.ps1 targets [-Only minmea]
#   .\poc\phase0\run.ps1 extract -Target <dir> [-Build "make"]   # one project, model.json only
param(
    [Parameter(Mandatory = $true, Position = 0)][ValidateSet("reproducers", "targets", "fetch", "extract")][string]$Mode,
    [string[]]$Only = @(),
    [string]$Target = "",
    [string]$Build = "make",
    [string]$Image = "framac-pipeline:latest"
)
$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path "$PSScriptRoot\..\..").Path
$Out = Join-Path $PSScriptRoot "out"
$Checkouts = Join-Path $Out "checkouts"
New-Item -ItemType Directory -Force $Out | Out-Null

if ($Mode -eq "fetch") {
    $ids = (Get-Content (Join-Path $PSScriptRoot "targets.json") -Raw | ConvertFrom-Json).PSObject.Properties.Name
    $targetArgs = @(); foreach ($id in $ids) { $targetArgs += @("--target", $id) }
    python -I (Join-Path $Repo "scripts\benchmark.py") fetch --work-dir $Checkouts @targetArgs
    exit $LASTEXITCODE
}

$mounts = @("-v", "${Repo}:/repo:ro", "-v", "${Out}:/out")
$onlyArgs = @(); if ($Only.Count) { $onlyArgs = @("--only") + $Only }
switch ($Mode) {
    "reproducers" { $cmd = @("python3", "-B", "/repo/poc/phase0/score.py", "reproducers", "--out", "/out/reproducers") + $onlyArgs }
    "targets" {
        $cmd = @("python3", "-B", "/repo/poc/phase0/score.py", "targets", "--checkouts", "/out/checkouts", "--out", "/out/targets") + $onlyArgs
    }
    "extract" {
        $abs = (Resolve-Path $Target).Path
        $mounts += @("-v", "${abs}:/target:ro")
        $name = Split-Path $abs -Leaf
        $cmd = @("python3", "-B", "/repo/poc/phase0/phase0b.py", "extract", "--target", "/target", "--out", "/out/extract/$name", "--build", $Build)
    }
}
docker run --rm --network none @mounts --entrypoint "" $Image @cmd
exit $LASTEXITCODE
