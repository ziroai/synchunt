"""
BugHuntRecon - Tool Execution Engine
Handles running external tools with proper error handling,
timeout management, and output capture.
"""

import os
import sys
import subprocess
import shlex
import time
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WINDOWS = sys.platform == 'win32'
from core.logger import BugHuntLogger


class ToolRunner:
    """Handles execution of external recon tools."""

    def __init__(self, logger=None, timeout=300, verbose=True):
        self.logger = logger or BugHuntLogger()
        self.default_timeout = timeout
        self.verbose = verbose
        self.running_processes = []

    def run(self, command, output_file=None, timeout=None, shell=False,
            tool_name="", cwd=None, env=None):
        """
        Run a tool command and capture output.

        Args:
            command: Command string or list
            output_file: File to save stdout output
            timeout: Command timeout in seconds
            shell: Whether to use shell execution
            tool_name: Name for logging
            cwd: Working directory
            env: Environment variables

        Returns:
            dict with stdout, stderr, returncode, success, duration
        """
        timeout = timeout or self.default_timeout
        tool_name = tool_name or (command.split()[0] if isinstance(command, str) else command[0])

        if self.verbose:
            self.logger.info(f"Running {tool_name}...")
            self.logger.debug(f"Command: {command}")

        start_time = time.time()

        try:
            if isinstance(command, str) and not shell:
                cmd = shlex.split(command)
            else:
                cmd = command

            # Merge environment
            run_env = os.environ.copy()
            if env:
                run_env.update(env)

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=run_env,
                shell=shell,
                preexec_fn=None if (IS_WINDOWS or shell) else os.setsid
            )

            self.running_processes.append(process)

            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Kill the process group
                try:
                    if IS_WINDOWS:
                        process.kill()
                    else:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        time.sleep(2)
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except Exception:
                    process.kill()

                stdout, stderr = process.communicate()
                self.logger.warning(
                    f"{tool_name} timed out after {timeout}s - partial results may be available"
                )

            self.running_processes.remove(process)

            duration = time.time() - start_time
            success = process.returncode == 0

            # Save output to file if specified
            if output_file and stdout:
                os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
                with open(output_file, 'w') as f:
                    f.write(stdout)

            # Count results
            result_count = len([l for l in stdout.strip().split('\n') if l.strip()]) if stdout else 0

            if success:
                self.logger.info(
                    f"{tool_name} completed in {duration:.1f}s - "
                    f"{result_count} results"
                )
            else:
                if stderr:
                    self.logger.warning(f"{tool_name} stderr: {stderr[:200]}")

            return {
                'stdout': stdout or '',
                'stderr': stderr or '',
                'returncode': process.returncode,
                'success': success,
                'duration': duration,
                'result_count': result_count,
                'output_file': output_file
            }

        except FileNotFoundError:
            self.logger.error(f"{tool_name} not found - is it installed?")
            return {
                'stdout': '',
                'stderr': f'{tool_name} not found',
                'returncode': -1,
                'success': False,
                'duration': 0,
                'result_count': 0,
                'output_file': output_file
            }
        except Exception as e:
            self.logger.error(f"{tool_name} failed: {str(e)}")
            return {
                'stdout': '',
                'stderr': str(e),
                'returncode': -1,
                'success': False,
                'duration': time.time() - start_time,
                'result_count': 0,
                'output_file': output_file
            }

    def run_parallel(self, commands, max_workers=5):
        """
        Run multiple commands in parallel.

        Args:
            commands: List of dicts with keys matching run() params
            max_workers: Maximum concurrent executions

        Returns:
            List of results
        """
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_cmd = {}
            for cmd_dict in commands:
                future = executor.submit(self.run, **cmd_dict)
                future_to_cmd[future] = cmd_dict.get(
                    'tool_name',
                    cmd_dict.get('command', 'unknown')
                )

            for future in as_completed(future_to_cmd):
                tool_name = future_to_cmd[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"{tool_name} raised exception: {e}")
                    results.append({
                        'stdout': '',
                        'stderr': str(e),
                        'returncode': -1,
                        'success': False,
                        'duration': 0,
                        'result_count': 0
                    })

        return results

    def run_with_stdin(self, command, stdin_data, output_file=None,
                       timeout=None, tool_name=""):
        """Run a command with data piped to stdin."""
        timeout = timeout or self.default_timeout
        tool_name = tool_name or (command.split()[0] if isinstance(command, str) else command[0])

        start_time = time.time()

        try:
            if isinstance(command, str):
                cmd = shlex.split(command)
            else:
                cmd = command

            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(
                input=stdin_data,
                timeout=timeout
            )

            duration = time.time() - start_time

            if output_file and stdout:
                os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
                with open(output_file, 'w') as f:
                    f.write(stdout)

            result_count = len([l for l in stdout.strip().split('\n') if l.strip()]) if stdout else 0

            self.logger.info(
                f"{tool_name} completed in {duration:.1f}s - "
                f"{result_count} results"
            )

            return {
                'stdout': stdout or '',
                'stderr': stderr or '',
                'returncode': process.returncode,
                'success': process.returncode == 0,
                'duration': duration,
                'result_count': result_count,
                'output_file': output_file
            }

        except Exception as e:
            self.logger.error(f"{tool_name} failed: {str(e)}")
            return {
                'stdout': '',
                'stderr': str(e),
                'returncode': -1,
                'success': False,
                'duration': time.time() - start_time,
                'result_count': 0,
                'output_file': output_file
            }

    def pipe_commands(self, commands, output_file=None, tool_name="pipeline"):
        """
        Run piped commands (cmd1 | cmd2 | cmd3).

        Args:
            commands: List of command strings
            output_file: File to save final output
            tool_name: Name for logging
        """
        pipe_cmd = ' | '.join(commands)
        return self.run(
            pipe_cmd,
            output_file=output_file,
            shell=True,
            tool_name=tool_name
        )

    def cleanup(self):
        """Kill all running processes."""
        for process in self.running_processes:
            try:
                if IS_WINDOWS:
                    process.kill()
                else:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        self.running_processes = []