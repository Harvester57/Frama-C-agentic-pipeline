<#
.SYNOPSIS
    Executes Frama-C, E-ACSL, Clang/LibFuzzer, or pipeline helper scripts inside the hardened framac-pipeline container.

.DESCRIPTION
    Mount layout:
      /target                    target C repository, READ-ONLY
      /framac-run                run directory (~/framac-pipeline/<repo>/run-<N>), read-write, working directory
      /opt/framac-pipeline/...   pipeline scripts, templates and schemas, read-only

    Container hardening: no network, all capabilities dropped, no-new-privileges, CPU/memory/PID limits,
    and an environment limited to an explicit allowlist. seccomp is relaxed only so that bubblewrap can
    create user namespaces for the inner sandbox around target-controlled binaries (scripts/sandbox_exec.py);
    -NoInnerSandbox keeps Docker's default seccomp profile, in which case target-controlled execution fails
    closed unless -AllowDegradedSandbox is also given.

.PARAMETER TargetDir
    Path to the target C repository on the host. Defaults to the current directory.

.PARAMETER RunDir
    Existing or new run directory. Must be outside the target unless -AllowRunDirInTarget is given and git ignores it.

.PARAMETER NewRun
    Create the next ~/framac-pipeline/<repo>/run-<N> directory and use it.

.PARAMETER RepoName
    Stable repository identifier. Defaults to the target directory name.

.PARAMETER Command
    Command string executed inside the container (bash -lc) with /framac-run as working directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetDir = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [string]$RunDir,

    [Parameter(Mandatory = $false)]
    [switch]$NewRun,

    [Parameter(Mandatory = $false)]
    [string]$RepoName,

    [Parameter(Mandatory = $false)]
    [string]$Image = "framac-pipeline:latest",

    [Parameter(Mandatory = $false)]
    [switch]$BuildIfMissing,

    [Parameter(Mandatory = $false)]
    [string]$Cpus = "4",

    [Parameter(Mandatory = $false)]
    [string]$Memory = "8g",

    [Parameter(Mandatory = $false)]
    [int]$PidsLimit = 4096,

    [Parameter(Mandatory = $false)]
    [switch]$NoInnerSandbox,

    [Parameter(Mandatory = $false)]
    [switch]$AllowDegradedSandbox,

    [Parameter(Mandatory = $false)]
    [switch]$AllowRunDirInTarget,

    [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Command
)

$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$PipelineRoot = Split-Path -Parent $PSScriptRoot
$ResolvedTarget = (Resolve-Path -Path $TargetDir).Path.TrimEnd('\', '/')

if (-not $RepoName) {
    $RepoName = Split-Path -Leaf $ResolvedTarget
}
if ($RepoName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
    throw "RepoName '$RepoName' must match ^[A-Za-z0-9][A-Za-z0-9._-]*$ (pass -RepoName explicitly)."
}

# ---- Resolve the run directory (outside the target by default) ----
if ($NewRun) {
    if ($RunDir) { throw "Use either -RunDir or -NewRun, not both." }
    $base = Join-Path (Join-Path $HOME "framac-pipeline") $RepoName
    New-Item -ItemType Directory -Force -Path $base | Out-Null
    $max = 0
    Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -match '^run-(\d+)$') { $n = [int]$Matches[1]; if ($n -gt $max) { $max = $n } }
    }
    $RunDir = Join-Path $base ("run-{0}" -f ($max + 1))
}
if (-not $RunDir) {
    throw "Specify -RunDir <path> (existing run) or -NewRun (creates ~/framac-pipeline/$RepoName/run-<N>)."
}
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
$ResolvedRun = (Resolve-Path -Path $RunDir).Path.TrimEnd('\', '/')

$targetPrefix = $ResolvedTarget + [IO.Path]::DirectorySeparatorChar
if ($ResolvedRun.StartsWith($targetPrefix, [StringComparison]::OrdinalIgnoreCase) -or $ResolvedRun -ieq $ResolvedTarget) {
    if (-not $AllowRunDirInTarget) {
        throw "Run directory '$ResolvedRun' is inside the target. Use a directory outside the target, or pass -AllowRunDirInTarget for a git-ignored path."
    }
    & git -C "$ResolvedTarget" check-ignore -q "$ResolvedRun" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Run directory '$ResolvedRun' is inside the target but not ignored by git."
    }
}
Write-Host "[framac-docker] run dir: $ResolvedRun"

# ---- Image ----
$imageExists = docker images "-q" "$Image" 2>$null
if (-not $imageExists) {
    if ($BuildIfMissing) {
        Write-Host "[framac-docker] Building Docker image $Image from $PipelineRoot..."
        docker build "-t" "$Image" "$PipelineRoot"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build Docker image $Image"
        }
    } else {
        throw "Docker image '$Image' not found. Run with -BuildIfMissing or execute: docker build -t `"$Image`" `"$PipelineRoot`""
    }
}

$CmdString = $Command -join " "

$dockerArgs = @(
    "run", "--rm", "-i",
    "--network", "none",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--cpus", "$Cpus",
    "--memory", "$Memory",
    "--pids-limit", "$PidsLimit"
)
if (-not $NoInnerSandbox) {
    # Required only so bubblewrap can unshare a user namespace for the inner sandbox.
    $dockerArgs += @("--security-opt", "seccomp=unconfined")
}
$dockerArgs += @(
    "-e", "PYTHONIOENCODING=utf-8",
    "-e", "FRAMAC_OUTER_SANDBOX=docker-hardened",
    "-e", "FRAMAC_TARGET_HOST=$ResolvedTarget",
    "-e", "FRAMAC_REPO=$RepoName"
)
if ($AllowDegradedSandbox) {
    $dockerArgs += @("-e", "FRAMAC_SANDBOX_DEGRADED=1")
}
$dockerArgs += @(
    "-v", "${ResolvedTarget}:/target:ro",
    "-v", "${ResolvedRun}:/framac-run",
    "-v", "${PipelineRoot}/scripts:/opt/framac-pipeline/scripts:ro",
    "-v", "${PipelineRoot}/templates:/opt/framac-pipeline/templates:ro",
    "-v", "${PipelineRoot}/schemas:/opt/framac-pipeline/schemas:ro",
    "-w", "/framac-run",
    "$Image",
    "$CmdString"
)

& docker @dockerArgs
exit $LASTEXITCODE
