<#
.SYNOPSIS
    Executes Frama-C, E-ACSL, Clang/LibFuzzer, or pipeline helper scripts inside the hardened framac-pipeline container.

.DESCRIPTION
    Mount layout:
      /target                    target C repository, READ-ONLY
      /framac-run                run directory (~/framac-pipeline/<repo>/run-<N>), read-write, working directory
      /opt/framac-pipeline/...   pipeline scripts, templates, schemas, skills and docs/references, read-only
      /framac-cache              shared cross-run cache (broker path), read-only unless -CacheRw and an
                                 allowlisted command

    Container hardening: no network, all capabilities dropped, no-new-privileges, the engine's default seccomp
    and AppArmor/SELinux profiles, CPU/memory/PID limits, and an environment limited to an explicit allowlist.
    The container is the isolation boundary. Inside it, target-controlled binaries run through
    scripts/sandbox_exec.py (rlimits, environment allowlist, timeout); there is no filesystem isolation
    inside the container.

    Sizing: by default the host broker (scripts/resources.py exec, needs a host Python >= 3.10 found as
    py -3, python3 or python) measures the machine on every call, takes a lease for the job class (inferred
    from the command unless -Class) and starts the container with --cpus/--memory/--pids-limit from that
    lease, so concurrent containers never oversubscribe the machine; when a gated lease releases and no
    tickets are waiting, running elastic containers are grown via `<engine> update` (never shrunk).
    -Cpus/-Memory/-PidsLimit (or FRAMAC_CPUS/FRAMAC_MEMORY/FRAMAC_PIDS_LIMIT) request a fixed grant, still
    registered with the broker. -NoBroker or FRAMAC_BROKER=off (and, with a warning, a missing host Python)
    keep the legacy static sizing: per-container -Cpus/-Memory/-PidsLimit divided by -Agents /
    FRAMAC_CONCURRENT_AGENTS.

    Engine: -Engine or FRAMAC_CONTAINER_ENGINE = docker | podman | auto (docker when usable).

    The legacy -NoInnerSandbox and -AllowDegradedSandbox switches are still declared so that old command
    lines bind, but bubblewrap has been removed and either switch now fails hard (exit code 2) before Docker
    runs. Drop them from your command line.

.PARAMETER TargetDir
    Path to the target C repository on the host. Defaults to the current directory.

.PARAMETER RunDir
    Existing or new run directory. Must be outside the target unless -AllowRunDirInTarget is given and git ignores it.

.PARAMETER NewRun
    Create the next ~/framac-pipeline/<repo>/run-<N> directory and use it.

.PARAMETER RepoName
    Stable repository identifier. Defaults to the target directory name.

.PARAMETER Class
    Job class for the host broker (light, wp, eva, build, guardrail, fuzz, replay, selftest, verify,
    phase-static, phase-dynamic). Defaults to the class inferred from the command.

.PARAMETER Engine
    Container engine: docker, podman or auto (default; docker when usable, else podman).

.PARAMETER NoBroker
    Skip the host broker and use the legacy static per-container limits (-Cpus/-Memory/-PidsLimit/-Agents).

.PARAMETER Agents
    Legacy (-NoBroker only): divide the default CPU/memory/PID limits by this many concurrent containers.

.PARAMETER CacheDir
    Shared cache directory on the host (default FRAMAC_CACHE_DIR or ~/.cache/framac-pipeline), or "off".

.PARAMETER CacheRw
    Writable shared cache for the allowlisted trusted commands. This is the default; it is kept for
    compatibility. FRAMAC_CACHE_RW=off mounts the shared cache read-only for every command.

.PARAMETER BuildImage
    Run the command in the build image (framac-build:latest; the target's own build and its tests, e.g.
    scripts/build_capture.py) instead of the monolith. With -TargetPackages, the derived build image
    framac-build:<repo> is built (--target framac-build) and used. -Image still overrides the image name.
    Every other command keeps the monolith (framac-pipeline:latest) as before.

.PARAMETER Scratch
    Create (once) and mount the run's named volume framac-scratch-<repo>-<run id>-<hash of the run dir>
    at /framac-scratch: the build capture's scratch tree and snapshot live there, not on the host bind
    mount. Every container of the run started with -Scratch sees the same volume at the same path.

.PARAMETER RemoveScratch
    Remove the run's scratch volume and exit (no command needed).

.PARAMETER Command
    Command string executed inside the container (bash -lc) with /framac-run as working directory.
    When referencing $S (the /opt/framac-pipeline/scripts shorthand), wrap the command in single
    quotes (e.g. -Command 'python3 $S/pipeline_make.py ...') or escape the dollar sign (`$S) so
    PowerShell on the host does not expand $S as an empty host variable.

.PARAMETER ScriptFile
    Host file whose contents are passed as the container command string (instead of -Command),
    avoiding host PowerShell quoting issues for multi-line scripts.

.PARAMETER NoInnerSandbox
    Removed (bubblewrap is no longer used). Passing it fails with exit code 2.

.PARAMETER AllowDegradedSandbox
    Removed (bubblewrap is no longer used). Passing it fails with exit code 2.
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
    [string]$TargetPackages = "",

    [Parameter(Mandatory = $false)]
    [switch]$BuildIfMissing,

    [Parameter(Mandatory = $false)]
    [switch]$BuildImage,

    [Parameter(Mandatory = $false)]
    [switch]$Scratch,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveScratch,

    [Parameter(Mandatory = $false)]
    [string]$Cpus = $(if ($env:FRAMAC_CPUS) { $env:FRAMAC_CPUS } else { [string][Environment]::ProcessorCount }),

    [Parameter(Mandatory = $false)]
    [string]$Memory = $(if ($env:FRAMAC_MEMORY) { $env:FRAMAC_MEMORY } else { "8g" }),

    [Parameter(Mandatory = $false)]
    [int]$Agents = $(if ($env:FRAMAC_CONCURRENT_AGENTS) { [int]$env:FRAMAC_CONCURRENT_AGENTS } else { 1 }),

    [Parameter(Mandatory = $false)]
    [int]$PidsLimit = $(if ($env:FRAMAC_PIDS_LIMIT) { [int]$env:FRAMAC_PIDS_LIMIT } else { 4096 }),

    [Parameter(Mandatory = $false)]
    [string]$Class = "",

    [Parameter(Mandatory = $false)]
    [string]$Engine = $(if ($env:FRAMAC_CONTAINER_ENGINE) { $env:FRAMAC_CONTAINER_ENGINE } else { "auto" }),

    [Parameter(Mandatory = $false)]
    [switch]$NoBroker,

    [Parameter(Mandatory = $false)]
    [string]$CacheDir = "",

    [Parameter(Mandatory = $false)]
    [switch]$CacheRw,

    # Legacy switches kept only so old command lines bind; both fail hard below.
    [Parameter(Mandatory = $false)]
    [switch]$NoInnerSandbox,

    [Parameter(Mandatory = $false)]
    [switch]$AllowDegradedSandbox,

    [Parameter(Mandatory = $false)]
    [switch]$AllowRunDirInTarget,

    [Parameter(Mandatory = $false)]
    [string]$ScriptFile = $null,

    [Parameter(Mandatory = $false, Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Command
)

$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ---- Reject unknown wrapper flags bound into $Command via ValueFromRemainingArguments ----
if ($Command -and $Command.Count -gt 0 -and $Command[0] -match '^-[A-Za-z]') {
    [Console]::Error.WriteLine(
        "[framac-docker] ERROR: unknown wrapper option '$($Command[0])'. " +
        "Valid options: -TargetDir, -RunDir, -NewRun, -RepoName, -Image, -TargetPackages, -BuildIfMissing, " +
        "-BuildImage, -Scratch, -RemoveScratch, " +
        "-Cpus, -Memory, -PidsLimit, -Class, -Engine, -NoBroker, -CacheDir, -CacheRw, -AllowRunDirInTarget, -ScriptFile, -Command."
    )
    exit 2
}

if (-not $RemoveScratch -and -not $ScriptFile -and (-not $Command -or $Command.Count -eq 0)) {
    [Console]::Error.WriteLine(
        "[framac-docker] ERROR: either a command or -ScriptFile is required. " +
        "Valid options: -TargetDir, -RunDir, -NewRun, -RepoName, -Image, -TargetPackages, -BuildIfMissing, " +
        "-BuildImage, -Scratch, -RemoveScratch, " +
        "-Cpus, -Memory, -PidsLimit, -Class, -Engine, -NoBroker, -CacheDir, -CacheRw, -AllowRunDirInTarget, -ScriptFile, -Command."
    )
    exit 2
}

if ($ScriptFile -and -not (Test-Path $ScriptFile -PathType Leaf)) {
    [Console]::Error.WriteLine("[framac-docker] ERROR: script file '$ScriptFile' does not exist")
    exit 2
}

# ---- Removed legacy sandbox switches: fail hard before anything else runs ----
foreach ($legacy in @("NoInnerSandbox", "AllowDegradedSandbox")) {
    if ($PSBoundParameters.ContainsKey($legacy)) {
        [Console]::Error.WriteLine(
            "[framac-docker] ERROR: -$legacy is no longer supported. The bubblewrap inner sandbox was removed; " +
            "the hardened container (default seccomp/AppArmor) is the isolation boundary and target-controlled " +
            "binaries run under scripts/sandbox_exec.py (rlimits, env allowlist, timeout). Drop -$legacy from the command line."
        )
        exit 2
    }
}

function Write-Warn([string]$Message) {
    [Console]::Error.WriteLine("[framac-docker] WARNING: $Message")
}

# A host Python >= 3.10 for the broker: FRAMAC_PYTHON, py -3, python3, python. The version probe rejects the
# Microsoft Store "python" stub (it prints nothing and exits non-zero when given arguments).
function Find-HostPython {
    $candidates = New-Object System.Collections.Generic.List[object]
    if ($env:FRAMAC_PYTHON) { $candidates.Add(@($env:FRAMAC_PYTHON)) }
    $candidates.Add(@("py", "-3"))
    $candidates.Add(@("python3"))
    $candidates.Add(@("python"))
    foreach ($cand in $candidates) {
        $exe = $cand[0]
        $pre = @()
        if ($cand.Count -gt 1) { $pre = @($cand[1..($cand.Count - 1)]) }
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $ver = $null
        try {
            $ver = & $exe @pre -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
            if ($LASTEXITCODE -ne 0) { $ver = $null }
        } catch {
            $ver = $null
        }
        if (-not $ver) { continue }
        $parts = ([string]($ver | Select-Object -First 1)).Trim().Split('.')
        $major = 0
        $minor = 0
        if ($parts.Count -lt 2 -or -not [int]::TryParse($parts[0], [ref]$major) -or -not [int]::TryParse($parts[1], [ref]$minor)) { continue }
        if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 10)) { return , (@($exe) + $pre) }
    }
    return $null
}

function Resolve-ContainerEngine([string]$Preference) {
    $pref = if ($Preference) { $Preference.ToLowerInvariant() } else { "auto" }
    if ($pref -eq "docker" -or $pref -eq "podman") {
        if (-not (Get-Command $pref -ErrorAction SilentlyContinue)) {
            [Console]::Error.WriteLine("[framac-docker] container engine '$pref' not found on PATH")
            exit 2
        }
        return $pref
    }
    if ($pref -ne "auto") {
        [Console]::Error.WriteLine("[framac-docker] invalid engine '$Preference' (docker|podman|auto)")
        exit 2
    }
    $hasDocker = [bool](Get-Command docker -ErrorAction SilentlyContinue)
    $hasPodman = [bool](Get-Command podman -ErrorAction SilentlyContinue)
    if ($hasDocker -and $hasPodman) {
        try { & docker info *> $null } catch {}
        if ($LASTEXITCODE -eq 0) { return "docker" }
        return "podman"
    }
    if ($hasDocker) { return "docker" }
    if ($hasPodman) { return "podman" }
    [Console]::Error.WriteLine("[framac-docker] no container engine found (install Docker or Podman, or set FRAMAC_CONTAINER_ENGINE)")
    exit 2
}

# ---- Container engine ----
$EngineName = Resolve-ContainerEngine $Engine
$OuterSandbox = "docker-hardened"
if ($EngineName -eq "podman") {
    $OuterSandbox = "podman-hardened"
} else {
    try {
        $engineVersion = & $EngineName --version 2>$null
        if ("$engineVersion" -match "podman") { $OuterSandbox = "podman-hardened" }
    } catch {}
}

# ---- Sizing path: host broker (default) or legacy static limits ----
$useBroker = (-not $NoBroker) -and ($env:FRAMAC_BROKER -ne "off")
$hostPython = $null
if ($useBroker) {
    $hostPython = Find-HostPython
    if (-not $hostPython) {
        Write-Warn "no host Python >= 3.10 found (tried FRAMAC_PYTHON, py -3, python3, python); using static per-container limits (as with -NoBroker)."
        $useBroker = $false
    }
}
if ($useBroker -and ($PSBoundParameters.ContainsKey("Agents") -or $env:FRAMAC_CONCURRENT_AGENTS)) {
    Write-Warn "-Agents / FRAMAC_CONCURRENT_AGENTS is deprecated and ignored: the host broker sizes every container from the measured pool (use -NoBroker for the legacy division)."
}

if (-not $useBroker -and $Agents -gt 1) {
    if (-not $PSBoundParameters.ContainsKey("Cpus") -and -not $env:FRAMAC_CPUS) {
        $divCpus = [Math]::Max(2, [int][Math]::Floor([Environment]::ProcessorCount / $Agents))
        $Cpus = [string]$divCpus
    }
    if (-not $PSBoundParameters.ContainsKey("Memory") -and -not $env:FRAMAC_MEMORY) {
        $memNum = 8
        if ($Memory -match '^(\d+)g$') { $memNum = [int]$Matches[1] }
        $divMem = [Math]::Max(2, [int][Math]::Floor($memNum / $Agents))
        $Memory = "${divMem}g"
    }
    if (-not $PSBoundParameters.ContainsKey("PidsLimit") -and -not $env:FRAMAC_PIDS_LIMIT) {
        $divPids = [Math]::Max(512, [int][Math]::Floor(4096 / $Agents))
        $PidsLimit = $divPids
    }
}

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
# Status lines go to stderr (as in framac-docker.sh): stdout carries only the command's output.
[Console]::Error.WriteLine("[framac-docker] run dir: $ResolvedRun")

# ---- SELinux (Linux hosts): relabel pipeline-owned mounts; the target needs an explicit choice ----
$z = ""
$zrw = ""
$zt = ""
$selinuxArgs = @()
$selinuxEnforcing = $false
try {
    if (Test-Path -LiteralPath "/sys/fs/selinux/enforce") {
        $selinuxEnforcing = ((Get-Content -LiteralPath "/sys/fs/selinux/enforce" -Raw).Trim() -eq "1")
    }
} catch {}
if ($selinuxEnforcing) {
    $z = ",z"
    $zrw = ":z"
    switch ($env:FRAMAC_SELINUX_TARGET) {
        "relabel" { $zt = ",z" }
        "disable" { $selinuxArgs = @("--security-opt", "label=disable") }
        default {
            [Console]::Error.WriteLine(
                "[framac-docker] SELinux is enforcing: set FRAMAC_SELINUX_TARGET=relabel to relabel the target " +
                "(shared container label, :z) or FRAMAC_SELINUX_TARGET=disable to run without SELinux confinement " +
                "(--security-opt label=disable)."
            )
            exit 2
        }
    }
}

# ---- Scratch volume: one named volume per run directory (repo, run id, and a hash of the run path) ----
$ScratchVolume = ""
if ($Scratch -or $RemoveScratch) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ResolvedRun))
    $runHash = (-join ($hashBytes | ForEach-Object { $_.ToString("x2") })).Substring(0, 12)
    $ScratchVolume = "framac-scratch-$RepoName-$(Split-Path -Leaf $ResolvedRun)-$runHash"
}
if ($RemoveScratch) {
    & $EngineName volume rm "-f" "$ScratchVolume" | Out-Null
    [Console]::Error.WriteLine("[framac-docker] removed scratch volume $ScratchVolume")
    exit $LASTEXITCODE
}

# ---- Image ----
# Build steps (-BuildImage) run in the build image (Dockerfile stage framac-build); everything else in the monolith.
$imageTarget = @()
if ($BuildImage) {
    if (-not $PSBoundParameters.ContainsKey("Image")) { $Image = "framac-build:latest" }
    $imageTarget = @("--target", "framac-build")
}
$imageExists = & $EngineName images "-q" "$Image" 2>$null
if (-not $imageExists) {
    if ($BuildIfMissing) {
        [Console]::Error.WriteLine("[framac-docker] Building image $Image with $EngineName from $PipelineRoot...")
        # Only stdout is piped: `2>&1` would turn the build's stderr progress into errors under "Stop".
        & $EngineName build @imageTarget "-t" "$Image" "$PipelineRoot" | ForEach-Object { [Console]::Error.WriteLine("$_") }
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build image $Image"
        }
    } else {
        throw "Image '$Image' not found. Run with -BuildIfMissing or execute: $EngineName build $($imageTarget -join ' ') -t `"$Image`" `"$PipelineRoot`""
    }
}

if ($TargetPackages) {
    $DerivedImage = "framac-pipeline:$RepoName"
    if ($BuildImage) { $DerivedImage = "framac-build:$RepoName" }
    [Console]::Error.WriteLine("[framac-docker] Building derived image $DerivedImage with target packages: $TargetPackages")
    & $EngineName build @imageTarget "-t" "$DerivedImage" "--build-arg" "TARGET_APT_PACKAGES=$TargetPackages" "$PipelineRoot" |
        ForEach-Object { [Console]::Error.WriteLine("$_") }
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build derived image $DerivedImage"
    }
    $Image = $DerivedImage
}

if ($Scratch) {
    & $EngineName volume inspect "$ScratchVolume" *> $null
    if ($LASTEXITCODE -ne 0) {
        & $EngineName volume create "--label" "framac.scratch=1" "$ScratchVolume" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to create scratch volume $ScratchVolume" }
        # A new volume's root belongs to root: open it (sticky, like /tmp) for the non-root job user.
        & $EngineName run "--rm" "--network" "none" "-v" "${ScratchVolume}:/framac-scratch" "--entrypoint" "/bin/chmod" "$Image" "1777" "/framac-scratch" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to initialize scratch volume $ScratchVolume" }
    }
    [Console]::Error.WriteLine("[framac-docker] scratch volume: $ScratchVolume at /framac-scratch")
}
$ImageId = ""
try {
    $inspected = & $EngineName image inspect "-f" "{{.Id}}" "$Image" 2>$null
    if ($LASTEXITCODE -eq 0 -and $inspected) { $ImageId = ([string]($inspected | Select-Object -First 1)).Trim() }
} catch {}

$RunId = Split-Path -Leaf $ResolvedRun
if ($ScriptFile) {
    $resolvedScript = (Resolve-Path $ScriptFile).Path
    $CmdString = [System.IO.File]::ReadAllText($resolvedScript, [System.Text.Encoding]::UTF8).Replace("`r`n", "`n")
} else {
    $CmdString = $Command -join " "
}
$TargetCommit = ""
$TargetDirty = ""
try {
    $gitRev = & git -C "$ResolvedTarget" rev-parse HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitRev) {
        $TargetCommit = ($gitRev | Select-Object -First 1).Trim()
        $gitSt = & git -C "$ResolvedTarget" status --porcelain "--untracked-files=no" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $TargetDirty = if ($gitSt) { "1" } else { "0" }
        }
    }
} catch {}

$hardeningArgs = @(
    "--rm", "-i",
    "--network", "none",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges"
)
# As in framac-docker.sh: on a Linux/macOS host, rootful Docker runs the job as the calling user so the run
# directory never collects root-owned files. Windows Docker Desktop bind mounts are not uid-owned, and
# Podman (rootless) maps the caller to the container's root already.
if ($OuterSandbox -eq "docker-hardened" -and ($IsLinux -or $IsMacOS)) {
    $hostUid = ([string](& id -u | Select-Object -First 1)).Trim()
    $hostGid = ([string](& id -g | Select-Object -First 1)).Trim()
    if ($LASTEXITCODE -ne 0 -or $hostUid -notmatch '^\d+$' -or $hostGid -notmatch '^\d+$') {
        throw "Could not determine the host uid/gid with 'id -u' / 'id -g'."
    }
    $hardeningArgs += @("--user", "${hostUid}:${hostGid}")
}
$envArgs = @(
    "-e", "PYTHONIOENCODING=utf-8",
    "-e", "S=/opt/framac-pipeline/scripts",
    "-e", "FRAMAC_OUTER_SANDBOX=$OuterSandbox",
    "-e", "FRAMAC_TARGET_HOST=$ResolvedTarget",
    "-e", "FRAMAC_REFERENCES_HOST=$PipelineRoot/docs/references",
    "-e", "FRAMAC_REPO=$RepoName",
    "-e", "FRAMAC_RUN_ID=$RunId",
    "-e", "FRAMAC_RUN_HOST=$ResolvedRun",
    "-e", "FRAMAC_TARGET_COMMIT=$TargetCommit",
    "-e", "FRAMAC_TARGET_DIRTY=$TargetDirty"
)
# Pipeline knobs that scripts read inside the container: forwarded when set on the host.
# Keep this list identical to framac-docker.sh and docker-compose.yml (tests/test_remediation_p2_container.py).
foreach ($knob in @("FRAMAC_CACHE", "FRAMAC_CACHE_MAX", "FRAMAC_MAX_AGENTS", "FRAMAC_SCHEDULER", "FRAMAC_LOCK_TIMEOUT",
                    "FRAMAC_LOCK_STALE", "FRAMAC_WP_WALL_TIMEOUT", "FRAMAC_PROVER_WALL_BUDGET_S", "FRAMAC_PROVER_CONTEXT",
                    "FRAMAC_FRAME_SKELETON", "FRAMAC_LOOP_TEMPLATES", "FRAMAC_SPEC_KB", "FRAMAC_RESOURCES_VERBOSE")) {
    $knobValue = [Environment]::GetEnvironmentVariable($knob)
    if ($knobValue) { $envArgs += @("-e", "$knob=$knobValue") }
}
$mountArgs = @(
    "-v", "${ResolvedTarget}:/target:ro$zt",
    "-v", "${ResolvedRun}:/framac-run$zrw",
    "-v", "${PipelineRoot}/scripts:/opt/framac-pipeline/scripts:ro$z",
    "-v", "${PipelineRoot}/templates:/opt/framac-pipeline/templates:ro$z",
    "-v", "${PipelineRoot}/schemas:/opt/framac-pipeline/schemas:ro$z",
    "-v", "${PipelineRoot}/skills:/opt/framac-pipeline/skills:ro$z",
    "-v", "${PipelineRoot}/docs/references:/opt/framac-pipeline/docs/references:ro$z"
)
if ($Scratch) { $mountArgs += @("-v", "${ScratchVolume}:/framac-scratch") }

if ($useBroker) {
    # resources.py exec leases CPUs/memory for the job class and inserts --name, --label, --init, the limits,
    # the job/pool environment and the shared cache mount after `run`. The command string travels in
    # FRAMAC_CONTAINER_CMD (no PowerShell -> Python -> engine re-quoting) and becomes the entry shim's argument.
    $env:FRAMAC_CONTAINER_CMD = $CmdString
    $env:FRAMAC_IMAGE_ID = $ImageId
    $env:FRAMAC_REPO = $RepoName  # partitions the shared cache per repository
    $pyExe = $hostPython[0]
    $pyPre = @()
    if ($hostPython.Count -gt 1) { $pyPre = @($hostPython[1..($hostPython.Count - 1)]) }
    $execArgs = @("$PipelineRoot/scripts/resources.py", "exec", "--run-dir", "$ResolvedRun")
    if ($Class) { $execArgs += @("--class", $Class) }
    if ($PSBoundParameters.ContainsKey("Cpus") -or $env:FRAMAC_CPUS) { $execArgs += @("--cpus", "$Cpus") }
    if ($PSBoundParameters.ContainsKey("Memory") -or $env:FRAMAC_MEMORY) { $execArgs += @("--memory", "$Memory") }
    if ($PSBoundParameters.ContainsKey("PidsLimit") -or $env:FRAMAC_PIDS_LIMIT) { $execArgs += @("--pids-limit", "$PidsLimit") }
    if ($CacheDir) { $execArgs += @("--cache-dir", $CacheDir) }
    if ($CacheRw) { $execArgs += "--cache-rw" }
    $execArgs += @("--", $EngineName, "run") + $hardeningArgs + $selinuxArgs + $envArgs + $mountArgs
    $execArgs += @("-w", "/framac-run", "--entrypoint", "/bin/bash", "$Image", "/opt/framac-pipeline/scripts/container_entry.sh")
    & $pyExe @pyPre @execArgs
    exit $LASTEXITCODE
}

$dockerArgs = @("run") + $hardeningArgs + @(
    "--cpus", "$Cpus",
    "--memory", "$Memory",
    "--pids-limit", "$PidsLimit"
) + $selinuxArgs
$dockerArgs += $envArgs + @("-e", "FRAMAC_IMAGE_ID=$ImageId")
$dockerArgs += $mountArgs + @(
    "-w", "/framac-run",
    "$Image",
    "$CmdString"
)

& $EngineName @dockerArgs
exit $LASTEXITCODE
