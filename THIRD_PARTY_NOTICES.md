# Attribution and dependencies

- Original winpspy: xct, https://github.com/xct/winpspy, baseline commit `b7a018c613e0100a577b35aac02809eb3d79b93f`. Upstream attribution is also included in the README.
- The retired upstream process-memory helper credited sonicmouse/ProcCmdLine: https://github.com/sonicmouse/ProcCmdLine. That helper is no longer compiled or used.
- Workflow inspiration: DominicBreuker/pspy, https://github.com/DominicBreuker/pspy. No Linux pspy implementation is incorporated.
- Microsoft.Diagnostics.Tracing.TraceEvent: https://github.com/microsoft/perfview (MIT). Package license and notices accompany the dependency.
- System.Management and System.Diagnostics.EventLog / .NET runtime: https://github.com/dotnet/runtime (MIT, with third-party notices in that repository).

Exact package versions and transitive dependencies are recorded in each project's `packages.lock.json`.
