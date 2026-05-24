"""Autofix API routes (mock Gemini + downstream services)."""

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from services.api.main import app
import services.api.main as api_main
from services.api.auth import create_organization_with_user
from services.database.database import Base
from services.database.models import Repository, Scan, Finding, FindingFixProposal

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[api_main.get_db] = override_get_db
api_main.SessionLocal = TestingSessionLocal
client = TestClient(app)


def _bootstrap_org_for_tests():
    db = TestingSessionLocal()
    try:
        org, _, raw_key = create_organization_with_user(
            db,
            org_name="Autofix Co",
            email="autofix-tester@example.com",
            password="supersecret",
        )
        return raw_key, org.id
    finally:
        db.close()


_TEST_API_KEY, _TEST_ORG_ID = _bootstrap_org_for_tests()
_AUTH = {"X-API-Key": _TEST_API_KEY}

VALID_SG_TF = '''resource "aws_security_group" "s" {
  vpc_id = "vpc-fake0123456789"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''


def _seed_scan_with_snapshot():
    db = TestingSessionLocal()
    repo = Repository(name="r1", url="https://github.com/acme/r1", org_id=_TEST_ORG_ID)
    db.add(repo)
    db.commit()
    db.refresh(repo)
    scan = Scan(
        repository_id=repo.id,
        org_id=_TEST_ORG_ID,
        pr_number=42,
        commit_sha="abc",
        status="completed",
        iac_files_snapshot={"main.tf": VALID_SG_TF},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    finding = Finding(
        scan_id=scan.id,
        org_id=_TEST_ORG_ID,
        finding_type="TEST_RULE",
        severity="HIGH",
        details={
            "resource_id": "aws_security_group.s",
            "explanation": "x",
            "remediation": "y",
            "source_file": "main.tf",
        },
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    sid, fid = scan.id, finding.id
    db.close()
    return sid, fid


def _seed_scan_with_two_findings():
    db = TestingSessionLocal()
    repo = Repository(name="r2", url="https://github.com/acme/r2", org_id=_TEST_ORG_ID)
    db.add(repo)
    db.commit()
    db.refresh(repo)
    scan = Scan(
        repository_id=repo.id,
        org_id=_TEST_ORG_ID,
        pr_number=43,
        commit_sha="def",
        status="completed",
        iac_files_snapshot={"main.tf": VALID_SG_TF},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    finding_one = Finding(
        scan_id=scan.id,
        org_id=_TEST_ORG_ID,
        finding_type="RULE_ONE",
        severity="HIGH",
        details={
            "resource_id": "aws_security_group.s",
            "explanation": "x",
            "remediation": "y",
            "source_file": "main.tf",
        },
    )
    finding_two = Finding(
        scan_id=scan.id,
        org_id=_TEST_ORG_ID,
        finding_type="RULE_TWO",
        severity="HIGH",
        details={
            "resource_id": "aws_security_group.s",
            "explanation": "x2",
            "remediation": "y2",
            "source_file": "main.tf",
        },
    )
    db.add_all([finding_one, finding_two])
    db.commit()
    db.refresh(finding_one)
    db.refresh(finding_two)
    sid, fid_one, fid_two = scan.id, finding_one.id, finding_two.id
    db.close()
    return sid, fid_one, fid_two


@patch("services.api.main.run_rescore_same_files")
@patch("services.api.main.propose_fix_json")
def test_propose_fix_persists_proposal(mock_propose, mock_rescore):
    mock_propose.return_value = {
        "fix_format": "edits",
        "edits": [
            {
                "path": "main.tf",
                "search": "0.0.0.0/0",
                "replace": "10.0.0.0/8",
            }
        ],
        "confidence": 0.9,
    }
    mock_rescore.return_value = (True, "ok", [])

    scan_id, finding_id = _seed_scan_with_snapshot()

    r = client.post(
        f"/api/scans/{scan_id}/findings/{finding_id}/propose-fix",
        json={},
        headers=_AUTH,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "validated"
    assert data["proposal_id"] >= 1

    db = TestingSessionLocal()
    row = db.query(FindingFixProposal).filter(FindingFixProposal.id == data["proposal_id"]).first()
    assert row is not None
    assert row.status == "validated"
    db.close()


@patch("services.api.main.run_rescore_same_files")
@patch("services.api.main.propose_fix_json")
def test_propose_fix_uses_validated_baseline_for_next_finding(mock_propose, mock_rescore):
    seen_snippets = []

    def _propose_side_effect(**kwargs):
        seen_snippets.append(kwargs.get("file_snippet", ""))
        return {
            "fix_format": "edits",
            "edits": [
                {
                    "path": "main.tf",
                    "search": "0.0.0.0/0" if len(seen_snippets) == 1 else "10.0.0.0/8",
                    "replace": "10.0.0.0/8" if len(seen_snippets) == 1 else "192.0.2.0/24",
                }
            ],
            "confidence": 0.9,
        }

    mock_propose.side_effect = _propose_side_effect
    mock_rescore.return_value = (True, "ok", [])
    scan_id, finding_one_id, finding_two_id = _seed_scan_with_two_findings()

    r1 = client.post(
        f"/api/scans/{scan_id}/findings/{finding_one_id}/propose-fix",
        json={},
        headers=_AUTH,
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["status"] == "validated"

    r2 = client.post(
        f"/api/scans/{scan_id}/findings/{finding_two_id}/propose-fix",
        json={},
        headers=_AUTH,
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["status"] == "validated"

    assert len(seen_snippets) == 2
    assert "10.0.0.0/8" in seen_snippets[1]


@patch("services.api.main.run_rescore_same_files")
@patch("services.api.main.propose_fix_json")
def test_propose_fixes_for_scan_endpoint(mock_propose, mock_rescore):
    mock_propose.return_value = {
        "fix_format": "edits",
        "edits": [{"path": "main.tf", "search": "0.0.0.0/0", "replace": "10.0.0.0/8"}],
        "confidence": 0.9,
    }
    mock_rescore.return_value = (True, "ok", [])
    scan_id, _, _ = _seed_scan_with_two_findings()
    response = client.post(
        f"/api/scans/{scan_id}/propose-fixes",
        json={},
        headers=_AUTH,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scan_id"] == scan_id
    assert body["count"] == 2
    assert len(body["items"]) == 2


@patch("services.api.main.post_pr_issue_comment")
def test_post_github_comment_accepts_owner_repo_slug_url(mock_post):
    mock_post.return_value = (
        201,
        {"id": 4242, "html_url": "https://github.com/acme/r1/issues/42#issuecomment-4242"},
    )
    scan_id, finding_id = _seed_scan_with_snapshot()
    db = TestingSessionLocal()
    repo = db.query(Repository).filter(Repository.name == "r1").first()
    repo.url = "acme/r1"
    proposal = FindingFixProposal(
        scan_id=scan_id,
        finding_id=finding_id,
        status="validated",
        unified_diff_preview="--- a/main.tf\n+++ b/main.tf\n",
    )
    db.add(proposal)
    db.commit()
    db.refresh(proposal)
    proposal_id = proposal.id
    db.close()

    response = client.post(
        f"/api/fix-proposals/{proposal_id}/post-github-comment",
        json={},
        headers=_AUTH,
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["posted"] is True
    assert data["github_comment_id"] == "4242"
    assert data["repository"] == "acme/r1"
    mock_post.assert_called_once()
