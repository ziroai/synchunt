"""
SyncHunt - Tool Execution Engine
Runs external tools with timeout management, process-group cleanup,
stdin piping and structured results. No shell is used by default.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from core.logger import BugHuntLogger

IS_WINDOWS = sys.platform == "win32"


def _empty_result(
    tool_name: str,
    output_file: Optional[str] = None,
    stderr: str = "",
    returncode: int = -1,
    skipped: bool = False,
    duration: float = 0.0,
) -> Dict[str, Any]:
    return {
        "stdout": "",
        "stderr": stderr,
        "returncode": returncode,
        "success": False,
        "skipped": skipped,
        "duration": duration,
        "result_count": 0,
        "output_file": output_file,
        "tool": tool_name,
    }


class ToolRunner:
    """Executes external recon tools and captures their output."""

    def __init__(self, logger: Optional[BugHuntLogger] = None, timeout: int = 300,
                 verbose: bool = True):
        self.logger = logger or BugHuntLogger()
        self.default_timeout = timeout
        self.verbose = verbose
        self.running_processes: List[subprocess.Popen] = []
        self._which_cache: Dict[str, Optional[str]] = {}

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------
    def which(self, tool: str) -> Optional[str]:
        """Cached `shutil.which`."""
        if tool not in self._which_cache:
            self._which_cache[tool] = shutil.which(tool)
        return self._which_cache[tool]

    def is_available(self, tool: str) -> bool:
        return self.which(tool) is not None

    def require(self, tool: str, output_file: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Return None when the tool is available, otherwise a skipped result.

        Usage:
            skipped = runner.require('nuclei')
            if skipped:
                return skipped
        """
        if self.is_available(tool):
            return None
        if self.verbose:
            self.logger.debug(f"{tool} is not installed - skipping")
        return _empty_result(
            tool, output_file=output_file,
            stderr=f"{tool} is not installed", skipped=True,
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def run(
        self,
        command: Union[str, Sequence[str]],
        output_file: Optional[str] = None,
        timeout: Optional[int] = None,
        shell: bool = False,
        tool_name: str = "",
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        stdin_data: Optional[str] = None,
        append: bool = False,
    ) -> Dict[str, Any]:
        """
        Run a tool command and capture output.

        Args:
            command: argv list (preferred) or a string parsed with shlex.
            output_file: File to save stdout to.
            timeout: Seconds before the process group is killed.
            shell: Only for commands that genuinely need shell features.
            tool_name: Label used in logs.
            stdin_data: Optional string piped to the process.
            append: Append to output_file instead of truncating it.
        """
        timeout = timeout or self.default_timeout

        if isinstance(command, str):
            argv: List[str] = shlex.split(command) if not shell else [command]
            display = command
        else:
            argv = [str(part) for part in command]
            display = " ".join(argv)

        tool_name = tool_name or (os.path.basename(argv[0]) if argv else "unknown")

        # Refuse to run anything that isn't installed, instead of raising later.
        if not shell and argv and not self.is_available(argv[0]):
            if self.verbose:
                self.logger.debug(f"{tool_name} is not installed - skipping")
            return _empty_result(
                tool_name, output_file, f"{tool_name} not found", skipped=True
            )

        if self.verbose:
            self.logger.debug(f"Command: {display}")

        start_time = time.time()
        try:
            run_env = os.environ.copy()
            if env:
                run_env.update(env)

            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if stdin_data is not None else None,
                text=True,
                cwd=cwd,
                env=run_env,
                shell=shell,
                preexec_fn=None if (IS_WINDOWS or shell) else os.setsid,
            )
            self.running_processes.append(process)

            try:
                stdout, stderr = process.communicate(input=stdin_data, timeout=timeout)
            except subprocess.TimeoutExpired:
                self._kill_process_group(process)
                stdout, stderr = process.communicate()
                self.logger.warning(
                    f"{tool_name} timed out after {timeout}s - partial results kept"
                )

            try:
                self.running_processes.remove(process)
            except ValueError:  # pragma: no cover - defensive
                pass

            duration = time.time() - start_time
            if output_file and stdout:
                os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
                mode = "a" if append else "w"
                with open(output_file, mode) as fh:
                    fh.write(stdout)

            result_count = sum(1 for line in (stdout or "").splitlines() if line.strip())
            result = {
                "stdout": stdout or "",
                "stderr": stderr or "",
                "returncode": process.returncode,
                "success": process.returncode == 0,
                "skipped": False,
                "duration": duration,
                "result_count": result_count,
                "output_file": output_file,
                "tool": tool_name,
            }

            if process.returncode == 0:
                if self.verbose:
                    self.logger.debug(
                        f"{tool_name} completed in {duration:.1f}s "
                        f"({result_count} output lines)"
                    )
            else:
                snippet = (stderr or "").strip().splitlines()
                detail = snippet[0][:200] if snippet else f"exit code {process.returncode}"
                self.logger.warning(f"{tool_name} exited non-zero: {detail}")

            return result

        except FileNotFoundError:
            self.logger.error(f"{tool_name} not found - is it installed?")
            return _empty_result(
                tool_name, output_file, f"{tool_name} not found", skipped=True,
                duration=time.time() - start_time,
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error(f"{tool_name} failed: {exc}")
            return _empty_result(
                tool_name, output_file, str(exc), duration=time.time() - start_time
            )

    def run_parallel(self, commands: Iterable[Dict[str, Any]], max_workers: int = 5) -> List[Dict[str, Any]]:
        """Run multiple tool invocations in parallel."""
        results: List[Dict[str, Any]] = []
        commands = list(commands)
        if not commands:
            return results

        with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
            future_map = {}
            for cmd_dict in commands:
                kwargs = dict(cmd_dict)
                future = executor.submit(self.run, **kwargs)
                future_map[future] = kwargs.get("tool_name", "unknown")
            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # pragma: no cover - defensive
                    self.logger.error(f"{name} raised exception: {exc}")
                    results.append(_empty_result(name, stderr=str(exc)))
        return results

    def run_with_stdin(
        self,
        command: Union[str, Sequence[str]],
        stdin_data: str,
        output_file: Optional[str] = None,
        timeout: Optional[int] = None,
        tool_name: str = "",
    ) -> Dict[str, Any]:
        """Run a command with data piped to stdin (replaces `echo x | tool`)."""
        return self.run(
            command,
            output_file=output_file,
            timeout=timeout,
            tool_name=tool_name,
            stdin_data=stdin_data,
        )

    def pipe_commands(
        self,
        commands: Sequence[Union[str, Sequence[str]]],
        output_file: Optional[str] = None,
        tool_name: str = "pipeline",
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run a real shell pipeline (cmd1 | cmd2 | ...).

        Every argument is shlex-quoted, so only trusted internal values should
        ever be passed here.
        """
        from core.utils import quote_args

        parts = []
        for command in commands:
            if isinstance(command, str):
                parts.append(command)
            else:
                parts.append(quote_args(command))
        pipeline = " | ".join(parts)
        return self.run(
            pipeline,
            output_file=output_file,
            timeout=timeout,
            shell=True,
            tool_name=tool_name,
        )

    # ------------------------------------------------------------------
    def _kill_process_group(self, process: subprocess.Popen) -> None:
        try:
            if IS_WINDOWS:
                process.kill()
                return
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            time.sleep(1.5)
            if process.poll() is None:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    def cleanup(self) -> None:
        """Kill every process still owned by this runner."""
        for process in list(self.running_processes):
            self._kill_process_group(process)
        self.running_processes = []
