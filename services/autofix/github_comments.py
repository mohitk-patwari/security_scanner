"""
Post a markdown comment on a GitHub pull request conversation (issue comments API).

See: https://docs.github.com/en/rest/issues/comments#create-an-issue-comment
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Optional


_GH_SLUG_RE = re.compile(
    r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/#\s.?]+)",
    re.IGNORECASE,
)
_OWNER_REPO_RE = re.compile(r"^(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$")


def _normalize_repo_name(repo: str) -> str:
    return repo.removesuffix(".git").strip("/")


def parse_github_slug(repository_url: str) -> tuple[str, str] | None:
    """Return (owner, repo) from a GitHub URL or ``owner/repo`` slug."""
    text = (repository_url or "").strip()
    if not text:
        return None

    m = _GH_SLUG_RE.search(text)
    if m:
        return m.group("owner"), _normalize_repo_name(m.group("repo"))

    if text.startswith("http://") or text.startswith("https://"):
        return None

    slug = _OWNER_REPO_RE.match(text)
    if slug:
        return slug.group("owner"), _normalize_repo_name(slug.group("repo"))

    return None


def post_pr_issue_comment(
    *,
    repository_url: str,
    issue_number: int,
    body: str,
    token: str,
) -> tuple[int, dict]:
    slug = parse_github_slug(repository_url)
    if not slug:
        raise ValueError(f"Unable to parse owner/repo from {repository_url!r}")
    owner, repo = slug
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
    data = json.dumps({"body": body}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = resp.read().decode("utf-8")
            code = resp.status
            return code, json.loads(payload) if payload else {}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API {exc.code}: {err_body}") from exc


def compose_fix_comment_md(
    *,
    finding_type: str,
    severity: str,
    scan_id: int,
    patched_preview_snippet: str,
) -> str:
    limited = patched_preview_snippet.strip()
    if len(limited) > 12000:
        limited = limited[:11900] + "\n…(truncated)\n"

    lines = [
        "## NetGuard proposed autofix",
        "",
        f"- Finding: **{finding_type}** ({severity})",
        f"- Scan: `{scan_id}`",
        "",
        "```diff",
        limited,
        "```",
        "",
        "*This is a suggestion only; review carefully before merging.*",
    ]
    return "\n".join(lines)
