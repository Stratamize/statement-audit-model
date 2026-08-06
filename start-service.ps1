# Start the Stratamize Statement Audit service on 127.0.0.1:8090 (loopback only).
# Optional: set STATEMENT_AUDIT_TOKEN before launching to require a bearer token.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }
& $python -m uvicorn service.app:app --app-dir $root --host 127.0.0.1 --port 8090
