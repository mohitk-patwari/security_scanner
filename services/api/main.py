import hmac
import hashlib
import json
import os
import difflib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Load repo-root `.env` before any `services.*` imports (cwd may not be project root when uvicorn starts).
# `main.py` lives at <repo>/services/api/main.py → parents[2] is the repo root (not parents[1], which is `services/`).
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_PROJECT_ROOT / ".env", override=True)

import httpx
from fastapi import Body, FastAPI, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from services.database.database import get_db, SessionLocal, Base, engine
from services.database.models import (
    Repository,
    Scan,
    Graph,
    Finding,
    FindingFixProposal,
    Override,
    Evaluation,
    Organization,
    User,
)
from services.api.auth import (
    create_organization_with_user,
    is_valid_email,
    issue_new_api_key,
    lookup_org_by_api_key,
    verify_password,
)

import logging
import time

from services.autofix.github_comments import (
    compose_fix_comment_md,
    parse_github_slug,
    post_pr_issue_comment,
)
from services.autofix.deterministic_fixes import try_deterministic_fix
from services.autofix.validators import (
    GRAPH_DEPENDENT_FINDING_TYPES,
    apply_edits,
    resolve_path_to_snapshot_key,
    run_rescore_same_files,
    validate_aws_security_group_rule_blocks,
    validate_patched_terraform_syntax,
)
from services.risk_scorer.llm.fix_client import propose_fix_json

logger = logging.getLogger("netguard.api")

app = FastAPI(
    title="NetGuard API",
    description="Backend API - orchestrates Parser, Graph Engine, and Risk Scorer services",
    version="0.1.0",
)

_CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "NETGUARD_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if o.strip()
]
_CORS_ORIGIN_REGEX = os.getenv(
    "NETGUARD_CORS_ORIGIN_REGEX",
    r"https?://(localhost|127\.0\.0\.1)(:\d+)?$|^https://[a-z0-9-]+\.vercel\.app$",
).strip() or None

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_origin_regex=_CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-API-Key"],
)


# Routes that bypass the API-key middleware entirely (login, signup, health).
_AUTH_PUBLIC_PATHS = {
    "/health",
    "/api/auth/signup",
    "/api/auth/login",
}

# `/api/scan` is special: CI calls it with an HMAC signature and no API key.
_HMAC_OK_PATHS = {"/api/scan"}


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Resolve `X-API-Key` -> Organization and stash on `request.state`.

    - Public paths (signup/login/health) pass through with no auth.
    - `/api/scan` accepts a valid `X-NetGuard-Signature` HMAC instead of an
      API key (used by GitHub Actions); the route handler then resolves the
      org from the signed payload's `api_key` field.
    - All other `/api/*` requests must carry a valid `X-API-Key` header.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path or ""
        method = (request.method or "").upper()

        # Always allow CORS preflight; non-/api routes bypass auth.
        if method == "OPTIONS" or not path.startswith("/api/"):
            return await call_next(request)

        if path in _AUTH_PUBLIC_PATHS:
            return await call_next(request)

        # Allow CI HMAC bypass for /api/scan (org is resolved inside the route).
        if path in _HMAC_OK_PATHS and request.headers.get("X-NetGuard-Signature"):
            return await call_next(request)

        api_key = (request.headers.get("X-API-Key") or "").strip()
        if not api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing X-API-Key header. Sign in to obtain one."},
            )

        db = SessionLocal()
        try:
            org = lookup_org_by_api_key(db, api_key)
            if not org:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or expired API key."},
                )
            request.state.org_id = org.id
            request.state.org_name = org.name
            request.state.api_key = api_key
        finally:
            db.close()

        return await call_next(request)


app.add_middleware(APIKeyAuthMiddleware)


def _require_org_id(request: Request) -> int:
    """Return the authenticated org id from request state, or raise 401."""
    org_id = getattr(request.state, "org_id", None)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return int(org_id)


@app.on_event("startup")
def _create_tables_with_retry():
    for attempt in range(1, 11):
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables created/verified (attempt %d).", attempt)
            return
        except Exception as exc:
            logger.warning("create_all attempt %d failed: %s", attempt, exc)
            if attempt < 10:
                time.sleep(2)
    logger.error("Could not create tables after 10 attempts — requests will fail.")

PARSER_SERVICE_URL = os.getenv("PARSER_SERVICE_URL", "http://localhost:8001")
GRAPH_ENGINE_SERVICE_URL = os.getenv("GRAPH_ENGINE_SERVICE_URL", "http://localhost:8002")
RISK_SCORER_SERVICE_URL = os.getenv("RISK_SCORER_SERVICE_URL", "http://localhost:8003")
NETGUARD_API_URL = os.getenv("NETGUARD_API_URL", "http://localhost:8000")
NETGUARD_SECRET = os.getenv("NETGUARD_SECRET", "") or ""


def _mask_api_key(raw_key: str) -> str:
    if not raw_key:
        return ""
    if len(raw_key) <= 12:
        return raw_key
    return f"{raw_key[:8]}...{raw_key[-4:]}"


def _session_org_payload(request: Request, org: Organization, user: User | None) -> dict[str, Any]:
    """Fields shared by GET /api/me and GET /api/settings (authenticated session)."""
    current_api_key = str(getattr(request.state, "api_key", "") or "")
    return {
        "org_id": org.id,
        "org_name": org.name,
        "user_email": user.email if user else None,
        "api_key": current_api_key,
        "api_key_masked": _mask_api_key(current_api_key),
        "api_url": NETGUARD_API_URL,
        "hmac_secret": NETGUARD_SECRET,
    }


COMPLIANCE_TAG_MAP = {
    "SSH_EXPOSED_TO_PUBLIC": ["CIS_AWS", "NIST_AC", "SOC2_CC", "PCI_DSS"],
    "RDP_EXPOSED_TO_PUBLIC": ["CIS_AWS", "NIST_AC", "SOC2_CC", "PCI_DSS"],
    "PUBLIC_DB_PORT_EXPOSED": ["CIS_AWS", "NIST_SC", "PCI_DSS"],
    "PUBLIC_S3_BUCKET": ["CIS_AWS", "NIST_SC", "SOC2_CC"],
    "ALL_PORTS_OPEN": ["CIS_AWS", "NIST_AC"],
    "HTTP_WITHOUT_HTTPS": ["CIS_AWS", "NIST_SC", "PCI_DSS"],
    "PERMISSIVE_IAM_POLICY": ["CIS_AWS", "NIST_AC", "SOC2_CC"],
    "MISSING_NETWORK_POLICY": ["CIS_KUBERNETES", "NIST_SC"],
    "PRIVILEGED_CONTAINER": ["CIS_KUBERNETES", "NIST_AC"],
    "UNAUTHENTICATED_SERVICE": ["CIS_KUBERNETES", "SOC2_CC"],
    "UNENCRYPTED_STORAGE": ["CIS_AWS", "NIST_SC", "PCI_DSS"],
    "MISSING_TAGS": ["SOC2_CC"],
    "INTERNET_EXPOSED_ADMIN_EC2": ["NIST_AC", "NIST_SC", "SOC2_CC", "PCI_DSS"],
    "PRIVILEGED_EC2_TO_SENSITIVE_DB": ["NIST_AC", "NIST_SC", "PCI_DSS"],
    "PUBLIC_CHAIN_TO_DATABASE": ["NIST_SC", "PCI_DSS"],
    "OVERPERMISSIVE_SG_CHAIN": ["CIS_AWS", "NIST_AC"],
    "CROSS_AZ_REPLICATION_EXPOSURE": ["CIS_AWS", "NIST_SC"],
    "LATERAL_MOVEMENT_VIA_SG": ["NIST_AC", "SOC2_CC"],
    "MUTABLE_DOCKER_IMAGE": ["NIST_SA", "NIST_SR"],
    "MISSING_DEPENDENCY_LOCK": ["NIST_SA", "NIST_SR"],
    "STALE_DEPENDENCY_LOCK": ["NIST_SA", "NIST_SR"],
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _severity_rank(value: Any) -> int:
    ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if not isinstance(value, str):
        value = str(value) if value is not None else ""
    return ranks.get((value or "").upper(), 1)


def _github_permalink(
    repo_url: str | None,
    sha: str | None,
    path: str | None,
    line: Any,
) -> str | None:
    """Clickable GitHub blob URL with line anchor."""
    if not repo_url or not sha or not path or line is None:
        return None
    try:
        line_int = int(line)
    except (TypeError, ValueError):
        return None
    base = str(repo_url).rstrip("/")
    path_clean = str(path).lstrip("/")
    return f"{base}/blob/{sha}/{path_clean}#L{line_int}"


def _build_graph_resource(resource: dict[str, Any]) -> dict[str, Any]:
    inbound = resource.get("inbound_rules", [])
    rules = []
    for rule in inbound:
        try:
            port = int(str(rule.get("port", "0")).split("-")[0])
        except (ValueError, TypeError):
            port = 0
        rules.append(
            {
                "port": port,
                "protocol": str(rule.get("protocol", "tcp")),
                "cidr": str(rule.get("cidr", "0.0.0.0/0")),
            }
        )

    resource_type = resource.get("resource_type", "")
    normalized_type = (
        resource_type.replace("aws_", "")
        .replace("kubernetes_", "")
        .replace("aws_", "")
    )
    if normalized_type == "instance":
        normalized_type = "ec2_instance"
    return {
        "resource_id": resource.get("resource_id"),
        "type": normalized_type,
        "provider": resource.get("provider", "unknown"),
        "rules": rules,
    }


def _extract_graph_resources(graph_data: Any) -> list[dict[str, Any]]:
    """
    Normalize stored resources payloads into a plain resource list.

    Supports both historical shape {"resources": [..]} and nested shape
    {"resources": {"resources": [..]}}.
    """
    if not isinstance(graph_data, dict):
        return []
    raw = graph_data.get("resources", [])
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        nested = raw.get("resources", [])
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
    return []


def _merge_graph_resources(
    baseline_resources: list[dict[str, Any]],
    changed_resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Merge baseline + changed resources by resource_id, with changed resources
    overriding baseline entries when IDs collide.
    """
    merged_by_id: dict[str, dict[str, Any]] = {}
    ordered: list[str] = []

    for resource in baseline_resources:
        resource_id = resource.get("resource_id")
        if not resource_id:
            continue
        key = str(resource_id)
        if key not in merged_by_id:
            ordered.append(key)
        merged_by_id[key] = resource

    for resource in changed_resources:
        resource_id = resource.get("resource_id")
        if not resource_id:
            continue
        key = str(resource_id)
        if key not in merged_by_id:
            ordered.append(key)
        merged_by_id[key] = resource

    return [merged_by_id[key] for key in ordered]


def _match_override(finding: dict[str, Any], overrides: list[Override]) -> Override | None:
    finding_type = finding.get("finding_type")
    resource_id = finding.get("resource_id", "")
    for override in overrides:
        if override.finding_type != finding_type:
            continue
        pattern = override.resource_pattern or ""
        if pattern in ("*", "") or pattern in resource_id:
            return override
    return None


def _verify_hmac_signature(raw_payload: bytes, signature_header: str) -> bool:
    if not NETGUARD_SECRET:
        return True
    digest = hmac.new(
        NETGUARD_SECRET.encode("utf-8"),
        msg=raw_payload,
        digestmod=hashlib.sha256,
    ).hexdigest()
    normalized = signature_header.replace("sha256=", "").strip().lower()
    ok = hmac.compare_digest(digest, normalized)
    if not ok:
        logger.warning(
            "HMAC mismatch: expected=%s…, received=%s… — check that NETGUARD_SECRET "
            "in .env matches the GitHub Actions secret exactly.",
            digest[:12],
            normalized[:12],
        )
    return ok


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "api"}


@app.post("/api/auth/signup")
def auth_signup(payload: dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    """Create a new org + first user. Returns the raw API key once."""
    name = str(payload.get("name") or "").strip()
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "")

    if not name:
        raise HTTPException(status_code=400, detail="Organization name is required.")
    if not is_valid_email(email):
        raise HTTPException(status_code=400, detail="A valid email is required.")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="An account with that email already exists.")

    org, user, raw_key = create_organization_with_user(
        db,
        org_name=name,
        email=email,
        password=password,
    )
    return {
        "org_id": org.id,
        "org_name": org.name,
        "user_email": user.email,
        "api_key": raw_key,
        "message": "Copy this API key now — it will not be shown again.",
    }


@app.post("/api/auth/login")
def auth_login(payload: dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    """Verify password. Does NOT return API key (bcrypt is one-way). Use regenerate-key if needed."""
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "")
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required.")

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(status_code=500, detail="User has no organization. Contact support.")

    return {
        "org_id": org.id,
        "org_name": org.name,
        "user_email": user.email,
        "api_key": None,
        "message": "Login successful. If you need a fresh API key, use the regenerate-key endpoint.",
    }


@app.get("/api/me")
def auth_me(request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=401, detail="Org no longer exists.")
    user = db.query(User).filter(User.org_id == org.id).order_by(User.created_at.asc()).first()
    return _session_org_payload(request, org, user)


@app.get("/api/settings")
def get_settings(request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=401, detail="Org no longer exists.")
    user = db.query(User).filter(User.org_id == org.id).order_by(User.created_at.asc()).first()
    return _session_org_payload(request, org, user)


@app.post("/api/auth/regenerate-key")
def regenerate_api_key(request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=401, detail="Org no longer exists.")
    raw_key = issue_new_api_key(db, org)
    return {
        "org_id": org.id,
        "org_name": org.name,
        "api_key": raw_key,
        "api_key_masked": _mask_api_key(raw_key),
        "message": "API key regenerated. Update NETGUARD_API_KEY in all connected GitHub repos.",
    }


@app.post("/api/scan")
async def scan_iac(request: Request, db: Session = Depends(get_db)):
    raw_body = await request.body()
    signature_header = request.headers.get("X-NetGuard-Signature")
    hmac_authed = False
    if signature_header:
        if not _verify_hmac_signature(raw_body, signature_header):
            raise HTTPException(status_code=401, detail="Invalid signature")
        hmac_authed = True
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON body") from None

    files = payload.get("files", [])
    if not files:
        raise HTTPException(status_code=400, detail="No IaC files provided")

    # Resolve org: middleware authed via X-API-Key, or HMAC-signed CI provided
    # an api_key inside the body to identify the org.
    org_id: int | None = getattr(request.state, "org_id", None)
    if not org_id and hmac_authed:
        body_api_key = str(payload.get("api_key") or "").strip()
        if body_api_key:
            org_lookup = lookup_org_by_api_key(db, body_api_key)
            if not org_lookup:
                raise HTTPException(status_code=401, detail="Invalid api_key in signed payload.")
            org_id = org_lookup.id
    if not org_id:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Send X-API-Key, or HMAC-sign the request and include 'api_key' in the body.",
        )

    repository_name = payload.get("repository", "unknown-repo")
    repository_url = str(payload.get("repository_url") or "").strip()
    pr_number_raw = payload.get("pr_number")
    pr_number: int | None = None
    if pr_number_raw is not None and str(pr_number_raw).strip() != "":
        try:
            pr_number = int(pr_number_raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="pr_number must be an integer") from None
    commit_sha = payload.get("commit_sha")

    # Optional ephemeral GitHub PAT for this scan only — never persisted/logged.
    request_github_token = (
        request.headers.get("X-GitHub-Token")
        or str(payload.get("github_token") or "")
    ).strip() or None

    repo = (
        db.query(Repository)
        .filter(Repository.name == repository_name, Repository.org_id == org_id)
        .first()
    )
    canonical_url = repository_url or (
        f"https://github.com/{repository_name}"
        if "/" in repository_name and not repository_name.startswith("http")
        else repository_name
    )
    if not repo:
        repo = Repository(
            name=repository_name,
            url=canonical_url,
            org_id=org_id,
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)
    elif repository_url:
        if repo.url != canonical_url:
            repo.url = canonical_url
            db.commit()

    scan = Scan(
        repository_id=repo.id,
        org_id=org_id,
        pr_number=pr_number,
        commit_sha=commit_sha,
        status="running",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    # Stash the per-request github token on request.state so downstream helpers
    # (e.g. PR comment posting later in the flow) can use it without persisting.
    request.state.scan_github_token = request_github_token

    parsed_resources: list[dict[str, Any]] = []
    module_sources: list[dict[str, Any]] = []
    head_graph: dict[str, Any] = {}
    graph_resources: list[dict[str, Any]] = []
    diff_payload: dict[str, Any] = {}
    risk_payload: dict[str, Any] = {"findings": []}
    previous_scan: Scan | None = None

    def _abort_scan_failed(status_code: int, detail: Any) -> None:
        scan.status = "failed"
        db.commit()
        raise HTTPException(status_code=status_code, detail=detail)

    try:
        # Generous timeout: per-finding Gemini enrichment can be slow on larger scans.
        async with httpx.AsyncClient(timeout=300.0) as client:
            for file_data in files:
                filename = file_data.get("filename", "")
                content = file_data.get("content", "")
                parser_response = await client.post(
                    f"{PARSER_SERVICE_URL}/parse",
                    files={"file": (filename, content)},
                )
                parser_response.raise_for_status()
                parser_payload = parser_response.json()
                parsed_resources.extend(parser_payload.get("resources", []))
                module_sources.extend(parser_payload.get("module_sources", []))

            if not parsed_resources:
                _abort_scan_failed(
                    400,
                    "Parser returned no supported resources. Send .tf/.yml files, restart the parser "
                    "service after upgrading, and confirm PARSER_SERVICE_URL points to it.",
                )

            graph_resources = [_build_graph_resource(resource) for resource in parsed_resources]

            previous_scan = (
                db.query(Scan)
                .filter(
                    Scan.repository_id == repo.id,
                    Scan.org_id == org_id,
                    Scan.pr_number == pr_number,
                    Scan.id != scan.id,
                )
                .order_by(Scan.created_at.desc())
                .first()
            )

            previous_resources: list[Any] = []
            if previous_scan:
                prev_resources_record = (
                    db.query(Graph)
                    .filter(Graph.scan_id == previous_scan.id, Graph.graph_type == "resources")
                    .first()
                )
                if prev_resources_record:
                    previous_resources = _extract_graph_resources(prev_resources_record.graph_data)

            merged_graph_resources = _merge_graph_resources(previous_resources, graph_resources)
            graph_response = await client.post(
                f"{GRAPH_ENGINE_SERVICE_URL}/graph/build",
                json={"resources": merged_graph_resources},
            )
            graph_response.raise_for_status()
            head_graph = graph_response.json()

            diff_payload = {
                "added_nodes": [],
                "removed_nodes": [],
                "added_edges": [],
                "removed_edges": [],
                "modified_nodes": [],
                "newly_exposed": [],
                "no_longer_exposed": [],
                "exposure_delta": 0,
            }
            if previous_resources:
                diff_response = await client.post(
                    f"{GRAPH_ENGINE_SERVICE_URL}/graph/diff",
                    json={"base": previous_resources, "head": merged_graph_resources},
                )
                diff_response.raise_for_status()
                diff_payload = diff_response.json()

            graph_context = {
                "nodes": head_graph.get("nodes", []),
                "edges": head_graph.get("edges", []),
                "newly_exposed": diff_payload.get("newly_exposed", []),
                "exposure_delta": diff_payload.get("exposure_delta", 0),
            }

            risk_response = await client.post(
                f"{RISK_SCORER_SERVICE_URL}/score",
                json={"resources": parsed_resources, "graph_context": graph_context},
            )
            risk_response.raise_for_status()
            risk_payload = risk_response.json()

    except HTTPException:
        raise
    except httpx.HTTPStatusError as exc:
        scan.status = "failed"
        db.commit()
        preview = (exc.response.text[:2048] if exc.response is not None else "") or ""
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Downstream service returned an error",
                "url": str(exc.request.url),
                "status_code": exc.response.status_code if exc.response else None,
                "body": preview,
            },
        ) from exc
    except httpx.RequestError as exc:
        scan.status = "failed"
        db.commit()
        req_url = str(exc.request.url) if exc.request else ""
        raise HTTPException(
            status_code=503,
            detail={"message": "Downstream service unreachable", "url": req_url},
        ) from exc
    except json.JSONDecodeError as exc:
        scan.status = "failed"
        db.commit()
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Downstream service returned a non-JSON response (check service logs)",
                "error": str(exc),
            },
        ) from exc
    except Exception as exc:
        scan.status = "failed"
        db.commit()
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Scan pipeline error before saving results",
                "error": str(exc),
                "type": type(exc).__name__,
            },
        ) from exc

    try:
        node_blast = {
            node.get("id"): node.get("blast_radius", {"count": 0, "resources": []})
            for node in head_graph.get("nodes", [])
        }
        active_overrides = db.query(Override).filter(Override.active.is_(True)).all()
        changed_resource_ids = {
            str(item.get("resource_id"))
            for item in graph_resources
            if isinstance(item, dict) and item.get("resource_id")
        }

        previous_keys = set()
        if previous_scan:
            for old_finding in db.query(Finding).filter(Finding.scan_id == previous_scan.id).all():
                details = old_finding.details or {}
                resource_id = details.get("resource_id")
                previous_keys.add((resource_id, old_finding.finding_type))

        current_keys = set()
        persisted_findings = []
        for finding in risk_payload.get("findings", []):
            resource_id = finding.get("resource_id")
            finding_type = finding.get("finding_type") or "UNKNOWN"
            current_keys.add((resource_id, finding_type))

            override = _match_override(finding, active_overrides)
            _sev = finding.get("severity", "LOW")
            severity = _sev if isinstance(_sev, str) else str(_sev) if _sev is not None else "LOW"
            overridden = False
            override_id = None
            if override:
                overridden = True
                override_id = override.id
                if override.severity_override:
                    severity = override.severity_override

            blast_data = node_blast.get(resource_id, {"count": 0, "resources": []})
            compliance_tags = COMPLIANCE_TAG_MAP.get(finding_type, [])
            is_new = (resource_id, finding_type) not in previous_keys

            db_finding = Finding(
                scan_id=scan.id,
                org_id=org_id,
                finding_type=finding_type,
                severity=severity,
                details=finding,
                blast_radius_count=blast_data.get("count", 0),
                blast_radius_resources=blast_data.get("resources", []),
                compliance_tags=compliance_tags,
                is_new=is_new,
                overridden=overridden,
                override_id=override_id,
            )
            persisted_findings.append(db_finding)
            db.add(db_finding)

        resolved_count = 0
        if previous_scan:
            old_findings = db.query(Finding).filter(Finding.scan_id == previous_scan.id).all()
            for old in old_findings:
                details = old.details or {}
                key = (details.get("resource_id"), old.finding_type)
                resource_id = details.get("resource_id")
                in_scope = resource_id is not None and str(resource_id) in changed_resource_ids
                if in_scope and key not in current_keys and old.resolved_at is None:
                    old.resolved_at = _utcnow()
                    old.resolved_in_scan_id = scan.id
                    resolved_count += 1

        db.add(Graph(scan_id=scan.id, graph_type="head", graph_data=head_graph))
        db.add(Graph(scan_id=scan.id, graph_type="diff", graph_data=diff_payload))
        db.add(
            Graph(
                scan_id=scan.id,
                graph_type="resources",
                graph_data={
                    "resources": merged_graph_resources,
                    "changed_resources": graph_resources,
                },
            )
        )

        new_count = sum(1 for item in persisted_findings if item.is_new)
        unchanged_count = max(0, len(persisted_findings) - new_count)
        resolution_summary = {
            "new_findings": new_count,
            "resolved_findings": resolved_count,
            "unchanged_findings": unchanged_count,
        }
        scan.resolution_summary = resolution_summary
        scan.iac_files_snapshot = {
            str(f.get("filename") or ""): str(f.get("content") or "") for f in files
        }
        scan.status = "completed"
        db.commit()

        high_or_critical_blocking = any(
            _severity_rank(entry.severity) >= _severity_rank("HIGH") and not entry.overridden
            for entry in persisted_findings
        )

        return {
            "scan_id": scan.id,
            "repository": repository_name,
            "pr_number": pr_number,
            "summary": {
                "total": len(persisted_findings),
                "critical": sum(1 for f in persisted_findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in persisted_findings if f.severity == "HIGH"),
                "medium": sum(1 for f in persisted_findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in persisted_findings if f.severity == "LOW"),
            },
            "resolution_summary": resolution_summary,
            "module_sources": module_sources,
            "blocking": high_or_critical_blocking,
        }
    except SQLAlchemyError as exc:
        db.rollback()
        try:
            row = db.query(Scan).filter(Scan.id == scan.id).one_or_none()
            if row:
                row.status = "failed"
                db.commit()
        except SQLAlchemyError:
            db.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Database error while saving scan (is DATABASE_URL correct and Postgres running?)",
                "error": str(exc),
                "type": type(exc).__name__,
            },
        ) from exc
    except Exception as exc:
        db.rollback()
        try:
            row = db.query(Scan).filter(Scan.id == scan.id).one_or_none()
            if row:
                row.status = "failed"
                db.commit()
        except SQLAlchemyError:
            db.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Error while persisting scan results",
                "error": str(exc),
                "type": type(exc).__name__,
            },
        ) from exc


@app.get("/api/scans")
def list_scans(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    org_id = _require_org_id(request)
    query = db.query(Scan).filter(Scan.org_id == org_id).order_by(Scan.created_at.desc())
    total = query.count()
    scans = query.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [
            {
                "id": scan.id,
                "repository_id": scan.repository_id,
                "pr_number": scan.pr_number,
                "commit_sha": scan.commit_sha,
                "status": scan.status,
                "resolution_summary": scan.resolution_summary,
                "created_at": str(scan.created_at),
            }
            for scan in scans
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
    repo_url = repo.url if repo else ""
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    def _finding_row(finding: Finding) -> dict[str, Any]:
        details = finding.details if isinstance(finding.details, dict) else {}
        sf = details.get("source_file")
        sl = details.get("source_line")
        return {
            "id": finding.id,
            "finding_type": finding.finding_type,
            "severity": finding.severity,
            "details": finding.details,
            "blast_radius_count": finding.blast_radius_count,
            "blast_radius_resources": finding.blast_radius_resources,
            "compliance_tags": finding.compliance_tags,
            "is_new": finding.is_new,
            "overridden": finding.overridden,
            "source_file": sf,
            "source_line": sl,
            "github_url": _github_permalink(repo_url, scan.commit_sha, sf, sl),
        }

    return {
        "id": scan.id,
        "repository_id": scan.repository_id,
        "repository": repo.name if repo else None,
        "repository_url": repo_url,
        "pr_number": scan.pr_number,
        "commit_sha": scan.commit_sha,
        "status": scan.status,
        "resolution_summary": scan.resolution_summary,
        "created_at": str(scan.created_at),
        "findings": [_finding_row(finding) for finding in findings],
    }


@app.get("/api/scans/{scan_id}/graph")
def get_scan_graph(scan_id: int, request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Graph not found")
    graphs = db.query(Graph).filter(Graph.scan_id == scan_id).all()
    if not graphs:
        raise HTTPException(status_code=404, detail="Graph not found")
    result = {}
    for graph in graphs:
        result[graph.graph_type] = graph.graph_data
    return result


@app.get("/api/scans/{scan_id}/diff")
def get_scan_diff(scan_id: int, request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Diff not found")
    diff_graph = (
        db.query(Graph)
        .filter(Graph.scan_id == scan_id, Graph.graph_type == "diff")
        .first()
    )
    if not diff_graph:
        raise HTTPException(status_code=404, detail="Diff not found")
    return diff_graph.graph_data


def _unified_diff_file_maps(before: dict[str, str], after: dict[str, str]) -> str:
    parts: list[str] = []
    paths = sorted(set(before.keys()) | set(after.keys()))
    for path in paths:
        o = before.get(path, "")
        n = after.get(path, "")
        if o == n:
            continue
        o_lines = o.splitlines(keepends=True)
        if not o_lines:
            o_lines = [""]
        n_lines = n.splitlines(keepends=True)
        if not n_lines:
            n_lines = [""]
        parts.append(
            "\n".join(
                difflib.unified_diff(
                    o_lines,
                    n_lines,
                    fromfile=f"a/{path}",
                    tofile=f"b/{path}",
                    lineterm="",
                )
            )
        )
    return "\n\n".join(parts)


def _merge_validated_fix_previews(
    db: Session,
    scan_id: int,
    file_map: dict[str, str],
    *,
    latest_per_finding_only: bool,
) -> dict[str, str]:
    merged = dict(file_map)
    rows = (
        db.query(FindingFixProposal)
        .filter(
            FindingFixProposal.scan_id == scan_id,
            FindingFixProposal.status == "validated",
        )
        .order_by(FindingFixProposal.created_at.asc(), FindingFixProposal.id.asc())
        .all()
    )
    if latest_per_finding_only:
        latest_by_finding: dict[int, FindingFixProposal] = {}
        for row in rows:
            latest_by_finding[row.finding_id] = row
        rows = sorted(
            latest_by_finding.values(),
            key=lambda item: (item.created_at, item.id),
        )

    for row in rows:
        preview = row.patched_files_preview if isinstance(row.patched_files_preview, dict) else {}
        sk_list = list(merged.keys())
        for pth, body in preview.items():
            key = resolve_path_to_snapshot_key(str(pth), sk_list)
            if key is None and str(pth) in merged:
                key = str(pth)
            if key is None or key not in merged:
                continue
            merged[key] = str(body or "")
    return merged


@app.post("/api/scans/{scan_id}/findings/{finding_id}/propose-fix")
def propose_fix_for_finding(
    scan_id: int,
    finding_id: int,
    request: Request,
    payload: dict[str, Any] | None = Body(default=None),
    db: Session = Depends(get_db),
):
    """
    Generate Gemini-backed edit proposals, validate search/replace, optionally re-scan snapshot.
    Optional body: `{ "files": [{"filename":"...", "content":"..."}] }` when scan has no snapshot.
    """
    org_id = _require_org_id(request)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.scan_id == scan_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    details = finding.details if isinstance(finding.details, dict) else {}
    file_map: dict[str, str] = {}
    body = payload or {}

    snap = scan.iac_files_snapshot
    if isinstance(snap, dict):
        file_map = {str(k): str(v) for k, v in snap.items()}
    ov_files = body.get("files")
    if isinstance(ov_files, list):
        for item in ov_files:
            if isinstance(item, dict):
                fn = item.get("filename") or ""
                file_map[str(fn)] = str(item.get("content") or "")

    if not file_map:
        raise HTTPException(
            status_code=400,
            detail="No IaC file snapshot for this scan — re-run POST /api/scan or pass 'files' in the request body.",
        )

    apply_validated_fixes = bool(body.get("apply_validated_fixes", True))
    latest_per_finding_only = bool(body.get("apply_latest_per_finding_only", False))
    if apply_validated_fixes:
        file_map = _merge_validated_fix_previews(
            db,
            scan.id,
            file_map,
            latest_per_finding_only=latest_per_finding_only,
        )

    source_file = details.get("source_file")
    snippet = file_map.get(source_file or "", "") if source_file else ""
    rid = str(details.get("resource_id") or "")

    edits: list[dict[str, Any]] = []
    llm_payload: dict[str, Any] = {}
    val_errs: list[str] = []

    deterministic = False
    new_map = dict(file_map)

    det_map, det_ok, det_rationale = try_deterministic_fix(
        file_map,
        finding.finding_type,
        rid,
        source_file if isinstance(source_file, str) else None,
    )
    if det_ok:
        deterministic = True
        new_map = det_map
        llm_payload = {
            "fix_format": "edits",
            "edits": [],
            "unified_diff": None,
            "rationale": det_rationale,
            "confidence": 1.0,
            "requires_human_review": False,
            "deterministic_autofix": True,
        }

    if not deterministic:
        allow_retry = bool(body.get("llm_retry_on_validation_error", True))
        snippet_cap = snippet[:12000] if snippet else ""

        llm_payload = propose_fix_json(
            finding_type=finding.finding_type,
            severity=finding.severity,
            explanation=str(details.get("explanation") or ""),
            remediation=str(details.get("remediation") or ""),
            source_file=source_file,
            file_snippet=snippet_cap,
            validation_feedback=None,
        )

        if llm_payload.get("fix_format") == "edits" and isinstance(llm_payload.get("edits"), list):
            edits = [e for e in llm_payload["edits"] if isinstance(e, dict)]

        new_map, val_errs = apply_edits(file_map, edits)

        if allow_retry and val_errs and any("substring" in e.lower() for e in val_errs):
            feedback = (
                "Previous autofix edits failed validation. Rewrite JSON edits so every search string "
                "matches the CURRENT file excerpt exactly (whitespace and quotes). Errors:\n"
                + "\n".join(val_errs)
            )
            retry_payload = propose_fix_json(
                finding_type=finding.finding_type,
                severity=finding.severity,
                explanation=str(details.get("explanation") or ""),
                remediation=str(details.get("remediation") or ""),
                source_file=source_file,
                file_snippet=snippet_cap,
                validation_feedback=feedback,
            )
            retry_edits = []
            if retry_payload.get("fix_format") == "edits" and isinstance(retry_payload.get("edits"), list):
                retry_edits = [e for e in retry_payload["edits"] if isinstance(e, dict)]
            r_new, r_err = apply_edits(file_map, retry_edits)
            if len(r_err) < len(val_errs) or (not r_err and retry_edits):
                llm_payload = retry_payload
                edits = retry_edits
                new_map, val_errs = r_new, r_err

    if not val_errs and (edits or deterministic):
        tex = validate_patched_terraform_syntax(new_map)
        sgx = validate_aws_security_group_rule_blocks(new_map)
        val_errs = [*tex, *sgx]

    has_patch = any(file_map.get(k) != new_map.get(k) for k in set(file_map) | set(new_map))

    reg_ok: bool | None = None
    reg_detail = ""
    digest: list[dict[str, Any]] | None = None
    diff_text = ""
    regression_hint: dict[str, Any] | None = None

    if not val_errs and has_patch:
        diff_text = _unified_diff_file_maps(file_map, new_map)

        if finding.finding_type in GRAPH_DEPENDENT_FINDING_TYPES:
            reg_ok = True
            reg_detail = (
                "Graph-dependent finding: automated regression skipped. "
                "Run a full scan to confirm exposure and cross-resource predicates."
            )
        else:
            ok, msg, digest = run_rescore_same_files(
                new_map,
                rid,
                finding.finding_type,
            )
            reg_ok = ok
            reg_detail = msg
            if not ok and digest:
                for row in digest:
                    if row.get("resource_id") != rid:
                        continue
                    regression_hint = {"matching_finding_snapshot": row}
                    break

    if val_errs:
        status = "failed"
    elif not has_patch:
        status = "failed"
        reg_detail = reg_detail or (
            "No file changes produced" if deterministic else "No editable fix returned by model"
        )
    elif reg_ok:
        status = "validated"
    else:
        status = "failed"

    preview: dict[str, str] = {}
    for pth in file_map:
        if file_map.get(pth) != new_map.get(pth):
            preview[pth] = new_map.get(pth, "")

    proposal = FindingFixProposal(
        scan_id=scan.id,
        finding_id=finding.id,
        status=status,
        llm_proposal=llm_payload,
        validation_errors=val_errs or None,
        patched_files_preview=preview or None,
        regression_ok=reg_ok,
        regression_detail=reg_detail or None,
        regression_findings_digest=digest[:20] if digest else None,
        unified_diff_preview=diff_text[:50000] if diff_text else None,
    )
    db.add(proposal)
    db.commit()
    db.refresh(proposal)

    return {
        "proposal_id": proposal.id,
        "status": proposal.status,
        "validation_errors": val_errs,
        "llm_proposal": llm_payload,
        "regression_ok": reg_ok,
        "regression_detail": reg_detail,
        "regression_target_hint": regression_hint,
        "unified_diff_preview": proposal.unified_diff_preview,
        "patched_files_preview": preview,
    }


@app.post("/api/scans/{scan_id}/propose-fixes")
def propose_fixes_for_scan(
    scan_id: int,
    request: Request,
    payload: dict[str, Any] | None = Body(default=None),
    db: Session = Depends(get_db),
):
    org_id = _require_org_id(request)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.id.asc()).all()
    results: list[dict[str, Any]] = []
    for finding in findings:
        res = propose_fix_for_finding(
            scan_id=scan_id,
            finding_id=finding.id,
            request=request,
            payload=payload,
            db=db,
        )
        results.append(
            {
                "finding_id": finding.id,
                "proposal_id": res.get("proposal_id"),
                "status": res.get("status"),
                "regression_ok": res.get("regression_ok"),
                "regression_detail": res.get("regression_detail"),
                "validation_errors": res.get("validation_errors"),
            }
        )
    return {"scan_id": scan_id, "count": len(results), "items": results}


@app.get("/api/scans/{scan_id}/fixes")
def list_scan_fix_proposals(scan_id: int, request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = (
        db.query(FindingFixProposal)
        .filter(FindingFixProposal.scan_id == scan_id)
        .order_by(FindingFixProposal.created_at.desc())
        .all()
    )
    return {
        "items": [
            {
                "id": row.id,
                "finding_id": row.finding_id,
                "status": row.status,
                "validation_errors": row.validation_errors,
                "regression_ok": row.regression_ok,
                "regression_detail": row.regression_detail,
                "unified_diff_preview": row.unified_diff_preview,
                "github_comment_id": row.github_comment_id,
                "created_at": str(row.created_at),
            }
            for row in rows
        ]
    }


@app.post("/api/fix-proposals/{proposal_id}/post-github-comment")
def post_fix_proposal_github_comment(
    proposal_id: int,
    request: Request,
    payload: dict[str, Any] | None = Body(default=None),
    db: Session = Depends(get_db),
):
    """Post a conversational PR comment with the proposed diff.

    Token resolution order: ``X-GitHub-Token`` header, then ``github_token`` in
    the request body, then the server-side ``GITHUB_TOKEN`` env var. The
    request-supplied token is used only for this call and never logged or
    persisted.
    """
    org_id = _require_org_id(request)
    body = payload or {}
    token = (
        request.headers.get("X-GitHub-Token")
        or str(body.get("github_token") or "")
        or os.getenv("GITHUB_TOKEN", "")
    ).strip()
    if not token:
        raise HTTPException(
            status_code=503,
            detail=(
                "No GitHub token available. Pass one via X-GitHub-Token header, "
                "the 'github_token' body field, or set GITHUB_TOKEN on the server."
            ),
        )

    prop = db.query(FindingFixProposal).filter(FindingFixProposal.id == proposal_id).first()
    if not prop:
        raise HTTPException(status_code=404, detail="Fix proposal not found")

    scan = db.query(Scan).filter(Scan.id == prop.scan_id, Scan.org_id == org_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found for this organization")
    if scan.pr_number is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Scan has no PR number. GitHub comments require a PR scan "
                "(set pr_number in the CI scan payload or open a PR workflow run)."
            ),
        )

    repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
    if not repo or not repo.url:
        raise HTTPException(status_code=400, detail="Repository URL missing")

    slug = parse_github_slug(repo.url)
    if not slug:
        raise HTTPException(
            status_code=400,
            detail=f"Repository URL is not a valid GitHub slug: {repo.url!r}",
        )

    finding = db.query(Finding).filter(Finding.id == prop.finding_id).first()
    comment_md = compose_fix_comment_md(
        finding_type=finding.finding_type if finding else "UNKNOWN",
        severity=finding.severity if finding else "UNKNOWN",
        scan_id=scan.id,
        patched_preview_snippet=prop.unified_diff_preview or "",
    )

    owner, repo_name = slug
    try:
        _, gh_payload = post_pr_issue_comment(
            repository_url=repo.url,
            issue_number=int(scan.pr_number),
            body=comment_md,
            token=token,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    cid = str(gh_payload.get("id") or "")
    if not cid:
        raise HTTPException(status_code=502, detail="GitHub API returned no comment id")

    prop.github_comment_id = cid
    db.commit()

    return {
        "posted": True,
        "github_comment_id": cid,
        "repository": f"{owner}/{repo_name}",
        "pr_number": int(scan.pr_number),
        "comment_url": gh_payload.get("html_url"),
    }


@app.get("/api/repos")
def list_repositories(request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    repos = (
        db.query(Repository)
        .filter(Repository.org_id == org_id)
        .order_by(Repository.created_at.desc())
        .all()
    )
    return {
        "items": [
            {"id": repo.id, "name": repo.name, "url": repo.url, "created_at": str(repo.created_at)}
            for repo in repos
        ]
    }


@app.get("/api/stats")
def get_stats(request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    scans_count = db.query(Scan).filter(Scan.org_id == org_id).count()
    findings = db.query(Finding).filter(Finding.org_id == org_id).all()
    critical_open = sum(1 for f in findings if f.severity == "CRITICAL" and not f.resolved_at)
    latest_completed_scan = (
        db.query(Scan)
        .filter(Scan.org_id == org_id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .first()
    )
    active_findings = 0
    if latest_completed_scan:
        active_findings = db.query(Finding).filter(Finding.scan_id == latest_completed_scan.id).count()

    compliance_posture = {
        "CIS_AWS": {"failing": 0, "passing": 0},
        "CIS_KUBERNETES": {"failing": 0, "passing": 0},
        "NIST_AC": {"failing": 0, "passing": 0},
        "NIST_SA": {"failing": 0, "passing": 0},
        "NIST_SC": {"failing": 0, "passing": 0},
        "NIST_SR": {"failing": 0, "passing": 0},
        "SOC2_CC": {"failing": 0, "passing": 0},
        "PCI_DSS": {"failing": 0, "passing": 0},
    }
    for finding in findings:
        for tag in finding.compliance_tags or []:
            if tag in compliance_posture:
                compliance_posture[tag]["failing"] += 1

    return {
        "total_scans": scans_count,
        "open_critical_findings": critical_open,
        "active_findings": active_findings,
        "compliance_posture": compliance_posture,
    }


@app.post("/api/overrides")
def create_override(payload: dict[str, Any], db: Session = Depends(get_db)):
    override = Override(
        finding_type=payload.get("finding_type"),
        resource_pattern=payload.get("resource_pattern", "*"),
        severity_override=payload.get("severity_override"),
        justification=payload.get("justification", ""),
        created_by=payload.get("created_by", "system"),
        active=True,
    )
    db.add(override)
    db.commit()
    db.refresh(override)
    return {
        "id": override.id,
        "finding_type": override.finding_type,
        "resource_pattern": override.resource_pattern,
        "severity_override": override.severity_override,
        "active": override.active,
    }


@app.get("/api/overrides")
def list_overrides(active_only: bool = Query(default=False), db: Session = Depends(get_db)):
    query = db.query(Override)
    if active_only:
        query = query.filter(Override.active.is_(True))
    overrides = query.order_by(Override.created_at.desc()).all()
    return {
        "items": [
            {
                "id": override.id,
                "finding_type": override.finding_type,
                "resource_pattern": override.resource_pattern,
                "severity_override": override.severity_override,
                "justification": override.justification,
                "created_by": override.created_by,
                "active": override.active,
                "created_at": str(override.created_at),
            }
            for override in overrides
        ]
    }


@app.delete("/api/overrides/{override_id}")
def delete_override(override_id: int, db: Session = Depends(get_db)):
    override = db.query(Override).filter(Override.id == override_id).first()
    if not override:
        raise HTTPException(status_code=404, detail="Override not found")
    override.active = False
    override.deactivated_at = _utcnow()
    db.commit()
    return {"deleted": True, "id": override_id}


@app.post("/api/evaluations")
def create_evaluation(request: Request, payload: dict[str, Any], db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    scan_id = payload.get("scan_id")
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan_id is required")
    if not db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")
    eval_record = Evaluation(
        scan_id=scan_id,
        truepositive_count=payload.get("truepositive_count"),
        falsepositive_count=payload.get("falsepositive_count"),
        falsenegative_count=payload.get("falsenegative_count"),
        precision=payload.get("precision"),
        recall=payload.get("recall"),
        accuracy=payload.get("accuracy"),
        specificity=payload.get("specificity"),
        blast_radius_correctness=payload.get("blast_radius_correctness"),
        actionability=payload.get("actionability"),
        calibration=payload.get("calibration"),
    )
    db.add(eval_record)
    db.commit()
    db.refresh(eval_record)
    return {
        "id": eval_record.id,
        "scan_id": eval_record.scan_id,
        "precision": eval_record.precision,
        "recall": eval_record.recall,
        "accuracy": eval_record.accuracy,
        "specificity": eval_record.specificity,
        "blast_radius_correctness": eval_record.blast_radius_correctness,
        "actionability": eval_record.actionability,
        "calibration": eval_record.calibration,
    }


@app.get("/api/evaluations")
def list_evaluations(
    request: Request,
    scan_id: int | None = None,
    db: Session = Depends(get_db),
):
    org_id = _require_org_id(request)
    org_scan_ids = [
        row.id for row in db.query(Scan.id).filter(Scan.org_id == org_id).all()
    ]
    query = db.query(Evaluation).filter(Evaluation.scan_id.in_(org_scan_ids or [-1]))
    if scan_id is not None:
        query = query.filter(Evaluation.scan_id == scan_id)
    rows = query.order_by(Evaluation.created_at.desc()).all()
    return {
        "items": [
            {
                "id": row.id,
                "scan_id": row.scan_id,
                "truepositive_count": row.truepositive_count,
                "falsepositive_count": row.falsepositive_count,
                "falsenegative_count": row.falsenegative_count,
                "precision": row.precision,
                "recall": row.recall,
                "accuracy": row.accuracy,
                "specificity": row.specificity,
                "blast_radius_correctness": row.blast_radius_correctness,
                "actionability": row.actionability,
                "calibration": row.calibration,
                "created_at": str(row.created_at),
            }
            for row in rows
        ]
    }


@app.get("/api/evaluations/summary")
def evaluation_summary(request: Request, db: Session = Depends(get_db)):
    org_id = _require_org_id(request)
    org_scan_ids = [
        row.id for row in db.query(Scan.id).filter(Scan.org_id == org_id).all()
    ]
    rows = (
        db.query(Evaluation)
        .filter(Evaluation.scan_id.in_(org_scan_ids or [-1]))
        .all()
    )
    if not rows:
        return {
            "count": 0,
            "mean_precision": 0.0,
            "mean_recall": 0.0,
            "mean_accuracy": 0.0,
            "mean_specificity": 0.0,
            "mean_blast_radius_correctness": 0.0,
            "mean_actionability": 0.0,
            "mean_calibration": 0.0,
        }

    precision_values = [row.precision for row in rows if row.precision is not None]
    recall_values = [row.recall for row in rows if row.recall is not None]
    accuracy_values = [row.accuracy for row in rows if row.accuracy is not None]
    specificity_values = [row.specificity for row in rows if row.specificity is not None]
    blast_values = [row.blast_radius_correctness for row in rows if row.blast_radius_correctness is not None]
    actionability_values = [row.actionability for row in rows if row.actionability is not None]
    calibration_values = [row.calibration for row in rows if row.calibration is not None]
    mean_precision = sum(precision_values) / len(precision_values) if precision_values else 0.0
    mean_recall = sum(recall_values) / len(recall_values) if recall_values else 0.0
    return {
        "count": len(rows),
        "mean_precision": round(mean_precision, 4),
        "mean_recall": round(mean_recall, 4),
        "mean_accuracy": round(sum(accuracy_values) / len(accuracy_values), 4) if accuracy_values else 0.0,
        "mean_specificity": round(sum(specificity_values) / len(specificity_values), 4) if specificity_values else 0.0,
        "mean_blast_radius_correctness": round(sum(blast_values) / len(blast_values), 4) if blast_values else 0.0,
        "mean_actionability": round(sum(actionability_values) / len(actionability_values), 4) if actionability_values else 0.0,
        "mean_calibration": round(sum(calibration_values) / len(calibration_values), 4) if calibration_values else 0.0,
    }
