"""GitHub slug parsing and PR comment helper tests."""

from unittest.mock import patch

import pytest

from services.autofix.github_comments import compose_fix_comment_md, parse_github_slug, post_pr_issue_comment


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/iyertrisha/demo-guard", ("iyertrisha", "demo-guard")),
        ("https://github.com/iyertrisha/demo-guard.git", ("iyertrisha", "demo-guard")),
        ("iyertrisha/demo-guard", ("iyertrisha", "demo-guard")),
        ("git@github.com:acme/infra.git", ("acme", "infra")),
        ("", None),
    ],
)
def test_parse_github_slug(url, expected):
    assert parse_github_slug(url) == expected


def test_compose_fix_comment_md_includes_diff():
    body = compose_fix_comment_md(
        finding_type="PUBLIC_S3_BUCKET",
        severity="CRITICAL",
        scan_id=7,
        patched_preview_snippet="+ open\n",
    )
    assert "PUBLIC_S3_BUCKET" in body
    assert "```diff" in body


@patch("services.autofix.github_comments.urllib.request.urlopen")
def test_post_pr_issue_comment_uses_issue_api(mock_urlopen):
    class FakeResp:
        status = 201

        def read(self):
            return b'{"id": 99, "html_url": "https://github.com/a/b/issues/1#issuecomment-99"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    mock_urlopen.return_value = FakeResp()
    code, payload = post_pr_issue_comment(
        repository_url="acme/infra",
        issue_number=12,
        body="hello",
        token="ghp_test",
    )
    assert code == 201
    assert payload["id"] == 99
    req = mock_urlopen.call_args[0][0]
    assert req.full_url == "https://api.github.com/repos/acme/infra/issues/12/comments"
