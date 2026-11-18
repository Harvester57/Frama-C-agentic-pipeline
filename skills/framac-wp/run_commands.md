## How to run commands

You run on the host, not in the analysis container. Every command this brief gives (`python3 /opt/framac-pipeline/scripts/...`, `frama-c`, a binary you built) runs inside the container through the pipeline wrapper, which mounts the run and the target for you:

- PowerShell:

  ```powershell
  & "{pipeline_dir}/wrappers/framac-docker.ps1" -TargetDir "{target_dir}" -RunDir "{run_dir}" -ScriptFile "{run_dir}/agents/{agent_id}/scratch/cmd.sh"
  & "{pipeline_dir}/wrappers/framac-docker.ps1" -TargetDir "{target_dir}" -RunDir "{run_dir}" -Command '<command>'
  ```

- POSIX shell:

  ```sh
  "{pipeline_dir}/wrappers/framac-docker.sh" --target "{target_dir}" --run-dir "{run_dir}" --script-file "{run_dir}/agents/{agent_id}/scratch/cmd.sh"
  "{pipeline_dir}/wrappers/framac-docker.sh" --target "{target_dir}" --run-dir "{run_dir}" -- '<command>'
  ```

The paths inside the commands are container paths: `/framac-run` is the run directory `{run_dir}` and the container's working directory (so `agents/...` and `workspace/...` are relative to it), `/target` is the target `{target_dir}`, read-only, and `/opt/framac-pipeline` holds the pipeline's scripts, read-only. Never pass them to a host tool.

The container runs the command with `bash -lc`. A command that contains single quotes (most do: the quoted `--cppflags`, `--ldflags` and `--fingerprint` values) or spans several lines goes in a script file under your scratch directory, written with LF line endings and passed with `-ScriptFile` / `--script-file` (a host path). Read and edit your files on the host under `{run_dir}/agents/{agent_id}/scratch/`.

The wrapper is the only way to reach Docker. It takes a lease from the run's resource broker, labels the container with the run, mounts the run and the target, sets the run's limits and removes the container when the command ends. A container you start yourself has none of that, and a `docker exec` into another command's container runs in that command's cgroup and time limit and dies with it. Never run `docker run`, `docker exec` or `docker inspect` yourself. Never lower the core limit (`ulimit -c 0`): the wrapper sets it to 1 byte because, under Docker Desktop's piped `core_pattern`, a limit of 0 still writes the whole core dump.
