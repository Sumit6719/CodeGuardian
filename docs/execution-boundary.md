# CodeGuardian Process Execution Boundary

The process execution boundary intercepts process requests, parses command tokens structurally, resolves executable safety directories, and tracks descendants.

## Features

1. **Direct Executable Spawning (`shell: false`)**: Spawns processes directly without shell interpreters, rendering shell execution escapes impossible at the OS boundary.
2. **NPM Script Extraction**: Analyzes nested package script trees recursively to discover hidden shell operations or malicious commands before running `npm test`.
3. **Executable Resolution**: Discovers absolute paths for system binaries and blocks local workspace executables to mitigate PATH hijacking.
4. **Environment key scrubbing**: Sanitizes environment variables to prevent leakage of credentials or secret keys.

## Descendant Tracking and Lifecycle Management

### Platform Semantics

* **Unix/Linux/macOS**: Spawns processes inside a separate process group (`detached: true` in Node options). On timeout or termination, signals are sent to the negative PID (e.g. `process.kill(-pid, 'SIGKILL')`) to clean up all background descendants.
* **Windows**: Spawns processes normally and uses OS process tree relationships to terminate descendants recursively via `taskkill /F /T /PID <pid>`.

### Limitations

If a spawned process detaches itself from the child process group (e.g., Windows Job Object escapes or background daemonization) and exits immediately, the parent process exits successfully and CodeGuardian cannot track or kill those escaped background daemons. Use OS-level sandboxing (Docker) for absolute container confinement.
