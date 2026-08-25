"""Recording gateway for a Grandstream UCM PBX.

Exposes an allowlisted set of extensions and their call records to a third
party without ever handing over the UCM's own credentials. recording_url is a
self-contained signed link (HMAC over the real UCM filename) so it works as a
plain fetchable URL with no extra header, but only the gateway can mint one and
only for filenames it itself pulled from an allowed extension's CDR.
"""
import base64
import hashlib
import hmac
import logging
import os
import re
import ssl
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import requests
import urllib3
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from requests.adapters import HTTPAdapter
from requests.auth import HTTPDigestAuth
from starlette.background import BackgroundTask
from urllib3.util.ssl_ import create_urllib3_context

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

UCM_HOST = os.environ["UCM_HOST"]
UCM_PORT = int(os.environ.get("UCM_PORT", "8443"))
UCM_USER = os.environ["UCM_USER"]
UCM_PASS = os.environ["UCM_PASS"]
UCM_VERIFY_SSL = os.environ.get("UCM_VERIFY_SSL", "false").strip().lower() == "true"

ALLOWED_EXTENSIONS = {
    e.strip() for e in os.environ.get("ALLOWED_EXTENSIONS", "").split(",") if e.strip()
}
LOOKBACK_DAYS = int(os.environ.get("LOOKBACK_DAYS", "30"))
PAGE_SIZE = int(os.environ.get("CDR_PAGE_SIZE", "500"))
MAX_PAGES = int(os.environ.get("CDR_MAX_PAGES", "50"))

GATEWAY_HOST = os.environ.get("GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "8080"))
REQUESTS_PER_MINUTE = int(os.environ.get("REQUESTS_PER_MINUTE", "30"))

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
if not PUBLIC_BASE_URL:
    raise RuntimeError("PUBLIC_BASE_URL is not configured in .env (e.g. http://203.0.113.10:1587)")

DOWNLOAD_SIGNING_SECRET = os.environ["DOWNLOAD_SIGNING_SECRET"]

GATEWAY_NAME = os.environ.get("GATEWAY_NAME", "Customer PBX")
DEFAULT_LIMIT = 100
MAX_LIMIT = 500


def _parse_fixed_offset(offset_str: str) -> timezone:
    m = re.match(r"^([+-])(\d{2}):?(\d{2})$", offset_str.strip())
    if not m:
        raise RuntimeError(f"Invalid UCM_TIMEZONE_OFFSET: {offset_str!r} (expected e.g. +05:00)")
    sign, hh, mm = m.groups()
    delta = timedelta(hours=int(hh), minutes=int(mm))
    return timezone(-delta if sign == "-" else delta)


# UCM's CDR timestamps are naive local time; this says what that local time
# actually is so we can emit proper timezone-aware ISO8601 timestamps.
UCM_TZ = _parse_fixed_offset(os.environ.get("UCM_TIMEZONE_OFFSET", "+05:00"))

_raw_keys = os.environ.get("GATEWAY_API_KEYS", "")
API_KEYS: dict[str, str] = {}
for pair in _raw_keys.split(","):
    pair = pair.strip()
    if not pair or ":" not in pair:
        continue
    name, _, secret = pair.partition(":")
    if name and secret:
        API_KEYS[secret] = name

if not API_KEYS:
    raise RuntimeError("GATEWAY_API_KEYS is not configured in .env (format: name:secret,name2:secret2)")

TEMP_DIR = BASE_DIR / "temp_downloads"
TEMP_DIR.mkdir(exist_ok=True)

if not UCM_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class _LegacyTLSAdapter(HTTPAdapter):
    """UCM6204's embedded HTTPS server uses weak/old DH params that modern
    OpenSSL rejects by default (DH_KEY_TOO_SMALL). Lower the security level
    just for this connection instead of weakening TLS globally."""

    def _legacy_context(self):
        ctx = create_urllib3_context()
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        if not UCM_VERIFY_SSL:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._legacy_context()
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._legacy_context()
        return super().proxy_manager_for(*args, **kwargs)


ucm_session = requests.Session()
ucm_session.mount("https://", _LegacyTLSAdapter())

logger = logging.getLogger("gateway")
logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(BASE_DIR / "gateway_audit.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_handler)
logger.addHandler(logging.StreamHandler())

# UCM stores recordings under month subfolders, e.g. "2026-07/auto-....wav",
# so recordfiles/filename values may contain one or more safe path segments.
# ".." is explicitly blocked to prevent escaping the monitor directory.
FILENAME_RE = re.compile(r"^(?!.*\.\.)[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\.wav$")
FILENAME_MAX_LEN = 256

_lock = threading.Lock()
_rate_buckets: dict[str, list[float]] = {}


def _check_rate_limit(bucket_key: str) -> None:
    now = time.time()
    with _lock:
        bucket = _rate_buckets.setdefault(bucket_key, [])
        bucket[:] = [t for t in bucket if now - t < 60]
        if len(bucket) >= REQUESTS_PER_MINUTE:
            raise HTTPException(status_code=429, detail="Rate limit exceeded, try again shortly")
        bucket.append(now)


def verify_bearer_token(authorization: Optional[str] = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization[len("Bearer "):].strip()
    if not token or token not in API_KEYS:
        logger.warning("AUTH_FAIL")
        raise HTTPException(status_code=401, detail="Invalid bearer token")
    key_name = API_KEYS[token]
    _check_rate_limit(key_name)
    return key_name


def _sign_filename(filename: str) -> str:
    token_part = base64.urlsafe_b64encode(filename.encode()).decode().rstrip("=")
    sig = hmac.new(DOWNLOAD_SIGNING_SECRET.encode(), filename.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{token_part}.{sig}"


def _verify_download_token(token: str) -> Optional[str]:
    token_part, _, sig = token.partition(".")
    if not token_part or not sig:
        return None
    padding = "=" * (-len(token_part) % 4)
    try:
        filename = base64.urlsafe_b64decode(token_part + padding).decode()
    except Exception:
        return None
    expected_sig = hmac.new(DOWNLOAD_SIGNING_SECRET.encode(), filename.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected_sig):
        return None
    if len(filename) > FILENAME_MAX_LEN or not FILENAME_RE.match(filename):
        return None
    return filename


def _to_iso_utc(value: Optional[str]) -> Optional[str]:
    """UCM gives naive 'YYYY-MM-DD HH:MM:SS' local time; convert to UTC 'Z' format."""
    if not value:
        return None
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    dt_utc = dt.replace(tzinfo=UCM_TZ).astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_client_datetime(value: str) -> datetime:
    """Parse an incoming from/to/updated_since value into a naive datetime
    expressed in the UCM's local time, matching what cdrapi expects."""
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid datetime: {value}")
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(UCM_TZ).replace(tzinfo=None)


_STATUS_MAP = {
    "ANSWERED": "answered",
    "NO ANSWER": "missed",
    "BUSY": "rejected",
    "FAILED": "rejected",
}


def _map_status(disposition: Optional[str]) -> str:
    if not disposition:
        return "unknown"
    return _STATUS_MAP.get(disposition.strip().upper(), "unknown")


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(str(offset).encode()).decode().rstrip("=")


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    padding = "=" * (-len(cursor) % 4)
    try:
        return max(0, int(base64.urlsafe_b64decode(cursor + padding).decode()))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor")


def _cdr_query(extension: str, direction: str, start_time: str, end_time: str) -> list[dict]:
    records: list[dict] = []
    offset = 0
    for _ in range(MAX_PAGES):
        params = {
            "format": "JSON",
            "startTime": start_time,
            "endTime": end_time,
            "numRecords": PAGE_SIZE,
            "offset": offset,
            direction: extension,
        }
        url = f"https://{UCM_HOST}:{UCM_PORT}/cdrapi"
        resp = ucm_session.get(
            url,
            params=params,
            auth=HTTPDigestAuth(UCM_USER, UCM_PASS),
            verify=UCM_VERIFY_SSL,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json() if resp.text.strip() else {}
        page = data.get("cdr_root") or []
        records.extend(page)
        if len(page) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return records


def _first_recording_filename(recordfiles: Optional[str]) -> Optional[str]:
    if not recordfiles:
        return None
    for part in re.split(r"[@,;]", recordfiles):
        filename = part.strip().strip("\"'")
        if filename and len(filename) <= FILENAME_MAX_LEN and FILENAME_RE.match(filename):
            return filename
    return None


app = FastAPI(title="Grandstream Recording Gateway")


@app.get("/health")
def health(key_name: str = Depends(verify_bearer_token)):
    return {"ok": True, "name": GATEWAY_NAME}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc.detail)})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"error": "Invalid request parameters"})


@app.get("/managers")
def list_managers(
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: Optional[str] = Query(default=None),
    key_name: str = Depends(verify_bearer_token),
):
    all_managers = [{"id": ext, "name": ext, "active": True} for ext in sorted(ALLOWED_EXTENSIONS)]
    offset = _decode_cursor(cursor)
    page = all_managers[offset:offset + limit]
    next_cursor = _encode_cursor(offset + limit) if offset + limit < len(all_managers) else None
    return {"items": page, "next_cursor": next_cursor}


@app.get("/calls")
def list_calls(
    request: Request,
    manager_id: Optional[str] = Query(default=None, description="Restrict to one extension"),
    start: Optional[str] = Query(default=None, description="YYYY-MM-DD, legacy alias for 'from'"),
    end: Optional[str] = Query(default=None, description="YYYY-MM-DD, legacy alias for 'to'"),
    from_: Optional[str] = Query(default=None, alias="from", description="ISO8601, e.g. 2026-07-21T00:00:00Z"),
    to: Optional[str] = Query(default=None, description="ISO8601, e.g. 2026-07-22T00:00:00Z"),
    updated_since: Optional[str] = Query(default=None, description="ISO8601; overrides from/to if set"),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: Optional[str] = Query(default=None),
    key_name: str = Depends(verify_bearer_token),
):
    if manager_id is not None and manager_id not in ALLOWED_EXTENSIONS:
        logger.warning("DENY_MANAGER key=%s manager_id=%s ip=%s", key_name, manager_id, request.client.host)
        raise HTTPException(status_code=403, detail="manager_id not authorized for this API key")

    extensions = [manager_id] if manager_id else sorted(ALLOWED_EXTENSIONS)

    now_local = datetime.now(UCM_TZ).replace(tzinfo=None)
    if updated_since:
        # CDR API only filters on call *start* time, so this treats
        # "updated since X" as "started since X" -- close enough since these
        # records don't change after the call ends and calls are short.
        start_dt = _parse_client_datetime(updated_since)
        end_dt = now_local
    elif from_ or to:
        start_dt = _parse_client_datetime(from_) if from_ else now_local - timedelta(days=LOOKBACK_DAYS)
        end_dt = _parse_client_datetime(to) if to else now_local
    elif start or end:
        end_dt = datetime.strptime(end, "%Y-%m-%d") if end else now_local
        start_dt = datetime.strptime(start, "%Y-%m-%d") if start else end_dt - timedelta(days=LOOKBACK_DAYS)
    else:
        end_dt = now_local
        start_dt = end_dt - timedelta(days=LOOKBACK_DAYS)

    start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S")
    end_str = end_dt.strftime("%Y-%m-%dT%H:%M:%S")

    all_records = []
    for extension in extensions:
        for direction in ("caller", "callee"):
            try:
                all_records.extend(_cdr_query(extension, direction, start_str, end_str))
            except requests.RequestException as exc:
                logger.error(
                    "CDR_QUERY_FAILED key=%s ext=%s direction=%s err=%s",
                    key_name, extension, direction, exc,
                )
                raise HTTPException(status_code=502, detail="Failed to query UCM CDR API") from exc

    seen: dict[str, dict] = {}
    for record in all_records:
        key = record.get("cdr") or record.get("uniqueid") or f"{record.get('src')}|{record.get('dst')}|{record.get('start')}"
        seen[key] = record

    calls = []
    for record in seen.values():
        src = record.get("src") or ""
        dst = record.get("dst") or ""

        if src in ALLOWED_EXTENSIONS:
            manager = src
            client_phone = dst
            call_direction = "outbound"
        elif dst in ALLOWED_EXTENSIONS:
            manager = dst
            client_phone = src
            call_direction = "inbound"
        else:
            manager = record.get("channel_ext") or ""
            if manager not in ALLOWED_EXTENSIONS:
                continue
            client_phone = dst if src == manager else src
            call_direction = "unknown"

        client_name = record.get("caller_name") or None

        filename = _first_recording_filename(record.get("recordfiles"))
        recording_url = f"{PUBLIC_BASE_URL}/download/{_sign_filename(filename)}" if filename else None

        try:
            duration_seconds = int(record.get("duration") or 0)
        except (TypeError, ValueError):
            duration_seconds = 0

        calls.append({
            "id": record.get("cdr") or record.get("uniqueid"),
            "manager_id": manager,
            "started_at": _to_iso_utc(record.get("start")),
            "updated_at": _to_iso_utc(record.get("end")) or _to_iso_utc(record.get("start")),
            "direction": call_direction,
            "status": _map_status(record.get("disposition")),
            "client_phone": client_phone,
            "client_name": client_name,
            "duration_seconds": duration_seconds,
            "recording_url": recording_url,
        })

    calls.sort(key=lambda c: (c["started_at"] or "", c["id"] or ""))

    offset = _decode_cursor(cursor)
    page = calls[offset:offset + limit]
    next_cursor = _encode_cursor(offset + limit) if offset + limit < len(calls) else None

    logger.info(
        "LIST_CALLS key=%s manager_id=%s ip=%s total=%d returned=%d",
        key_name, manager_id, request.client.host, len(calls), len(page),
    )
    return {"items": page, "next_cursor": next_cursor}


def _cleanup(path: Path, filename: str) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        logger.error("CLEANUP_FAILED file=%s err=%s", path, exc)
    logger.info("DELIVERED_AND_DELETED filename=%s", filename)


@app.get("/download/{token}")
def download_by_token(request: Request, token: str):
    _check_rate_limit(f"ip:{request.client.host}")

    filename = _verify_download_token(token)
    if not filename:
        raise HTTPException(status_code=404, detail="Recording not found")

    temp_path = TEMP_DIR / f"{uuid.uuid4().hex}.wav"
    url = f"https://{UCM_HOST}:{UCM_PORT}/recapi"

    try:
        with ucm_session.get(
            url,
            params={"filedir": "monitor", "filename": filename},
            auth=HTTPDigestAuth(UCM_USER, UCM_PASS),
            verify=UCM_VERIFY_SSL,
            stream=True,
            timeout=60,
        ) as resp:
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail=f"UCM recapi returned {resp.status_code}")

            first_chunk = True
            with open(temp_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    if first_chunk:
                        first_chunk = False
                        if chunk[:1] in (b"{", b"[", b"<"):
                            raise HTTPException(status_code=502, detail="UCM returned an error instead of audio")
                    f.write(chunk)
    except requests.RequestException as exc:
        temp_path.unlink(missing_ok=True)
        logger.error("DOWNLOAD_FAILED filename=%s err=%s", filename, exc)
        raise HTTPException(status_code=502, detail="Failed to fetch recording from UCM") from exc
    except HTTPException:
        temp_path.unlink(missing_ok=True)
        raise

    if not temp_path.exists() or temp_path.stat().st_size < 44:
        temp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=502, detail="Downloaded recording looked invalid or empty")

    logger.info("DOWNLOAD_OK filename=%s ip=%s", filename, request.client.host)
    return FileResponse(
        path=temp_path,
        media_type="audio/wav",
        filename=filename.rsplit("/", 1)[-1],
        background=BackgroundTask(_cleanup, temp_path, filename),
    )


def _pid_is_running(pid: int) -> bool:
    import subprocess

    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True, text=True, timeout=10,
        )
        return str(pid) in out.stdout
    except Exception:
        return False


if __name__ == "__main__":
    import sys
    import uvicorn

    pid_file = BASE_DIR / "gateway.pid"
    if pid_file.exists():
        existing_pid_text = pid_file.read_text(encoding="utf-8").strip()
        if existing_pid_text.isdigit() and _pid_is_running(int(existing_pid_text)):
            print(f"Gateway already running with PID {existing_pid_text} (gateway.pid). Run stop.bat first.")
            sys.exit(1)
        pid_file.unlink(missing_ok=True)  # stale file from a crashed/killed run

    pid_file.write_text(str(os.getpid()), encoding="utf-8")
    for leftover in TEMP_DIR.glob("*.wav"):
        leftover.unlink(missing_ok=True)

    logger.info(
        "STARTUP host=%s port=%d ucm=%s:%d extensions=%s public_base=%s",
        GATEWAY_HOST, GATEWAY_PORT, UCM_HOST, UCM_PORT, sorted(ALLOWED_EXTENSIONS), PUBLIC_BASE_URL,
    )
    # pythonw.exe has no console, so sys.stdout is None there and uvicorn's
    # default logging setup crashes calling sys.stdout.isatty(). Only skip it
    # in that case; a real console (python.exe) gets uvicorn's normal logs.
    uvicorn_kwargs = {}
    if sys.stdout is None or sys.stderr is None:
        uvicorn_kwargs["log_config"] = None

    try:
        uvicorn.run(app, host=GATEWAY_HOST, port=GATEWAY_PORT, **uvicorn_kwargs)
    except Exception:
        logger.exception("STARTUP_FAILED")
        raise
    finally:
        pid_file.unlink(missing_ok=True)
