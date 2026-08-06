#!/usr/bin/env python3
"""Loopback HTTP service exposing the Stratamize statement-audit validator.

The service wraps ``tools/validate_audit.py`` without changing its rules.
Request bodies are read as raw bytes so the validator's own JSON parsing —
duplicate-key rejection, Decimal numbers, and number-safety limits — stays in
effect. Responses carry only rule codes, JSON Pointer paths, and fixed
messages; submitted values are never echoed.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import validate_audit  # noqa: E402

SERVICE_NAME = "stratamize-statement-audit"
TOKEN_ENV_VAR = "STATEMENT_AUDIT_TOKEN"
MAX_BODY_BYTES = validate_audit.MAX_INPUT_BYTES
PARSE_ERROR_CODES = {
    "duplicate_key",
    "input_depth",
    "input_size",
    "invalid_json",
    "invalid_root",
    "non_finite_number",
    "number_range",
}

app = FastAPI(
    title="Stratamize Statement Audit Model",
    version=validate_audit.VALIDATOR_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _error_report(code: str) -> dict:
    return {
        "validator_version": validate_audit.VALIDATOR_VERSION,
        "status": "invalid",
        "issue_count": 1,
        "issues": [
            {
                "code": code,
                "path": "/",
                "message": "Input could not be parsed as a safe audit record.",
            }
        ],
    }


def _issues_report(issues: list[validate_audit.ValidationIssue]) -> dict:
    return {
        "validator_version": validate_audit.VALIDATOR_VERSION,
        "status": "valid" if not issues else "invalid",
        "issue_count": len(issues),
        "issues": [issue.to_dict() for issue in issues],
    }


@app.middleware("http")
async def _require_token(request: Request, call_next) -> Response:
    expected = os.environ.get(TOKEN_ENV_VAR, "")
    if expected:
        header = request.headers.get("authorization", "")
        bearer = header.removeprefix("Bearer ") if header.startswith("Bearer ") else ""
        supplied = bearer or request.headers.get("x-audit-token", "")
        if not supplied or not secrets.compare_digest(supplied, expected):
            return JSONResponse(
                {"detail": "A valid service token is required."}, status_code=401
            )
    return await call_next(request)


async def _read_bounded_body(request: Request) -> bytes | None:
    """Read the request body, aborting as soon as it exceeds the byte cap.

    The cap is enforced while streaming so an oversized or lying
    Content-Length can never buffer more than one chunk past the limit.
    """
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return None
        except ValueError:
            return None
    received = bytearray()
    async for chunk in request.stream():
        received.extend(chunk)
        if len(received) > MAX_BODY_BYTES:
            return None
    return bytes(received)


@app.post("/api/validate")
async def validate_record(request: Request) -> JSONResponse:
    body = await _read_bounded_body(request)
    if body is None:
        return JSONResponse(_error_report("input_size"), status_code=413)
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeError:
        return JSONResponse(_error_report("input_read"), status_code=400)
    try:
        record = validate_audit.loads_record(text)
    except ValueError as exc:
        candidate = str(exc).split(":", maxsplit=1)[0]
        code = candidate if candidate in PARSE_ERROR_CODES else "invalid_json"
        return JSONResponse(_error_report(code), status_code=400)
    return JSONResponse(validate_audit.validation_result(record))


@app.post("/api/validate-csv")
async def validate_csv(request: Request) -> JSONResponse:
    body = await _read_bounded_body(request)
    if body is None:
        return JSONResponse(_error_report("input_size"), status_code=413)
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeError:
        return JSONResponse(_error_report("input_read"), status_code=400)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", suffix=".csv", delete=False
    )
    try:
        handle.write(text)
        handle.close()
        issues = validate_audit.validate_csv_template(handle.name)
    finally:
        os.unlink(handle.name)
    return JSONResponse(_issues_report(issues))


@app.get("/api/schema")
async def get_schema() -> JSONResponse:
    schema = json.loads(validate_audit.SCHEMA_PATH.read_text(encoding="utf-8"))
    return JSONResponse(schema)


@app.get("/api/corpus")
async def run_corpus() -> JSONResponse:
    report = validate_audit.build_corpus_report(ROOT)
    return JSONResponse(report)


@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse(
        {
            "service": SERVICE_NAME,
            "status": "ok",
            "version": validate_audit.VALIDATOR_VERSION,
        }
    )
