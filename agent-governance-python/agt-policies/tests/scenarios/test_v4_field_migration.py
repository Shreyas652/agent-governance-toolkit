# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OPA-backed regressions for v4 field and default-action migration."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from agt.cli._migrate_resolution import resolve_manifest

pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary required for scenario tests",
)


def _binding() -> dict:
    return {
        "pre_tool_call": {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "tool_name_from": "$.tool_call.name",
            "policy": {"id": "agt_legacy_rules"},
        }
    }


def _evaluate(bundle: Path, snapshot: dict) -> dict:
    proc = subprocess.run(
        [
            "opa",
            "eval",
            "--format",
            "raw",
            "--stdin-input",
            "--data",
            str(bundle),
            "data.agt.legacy.verdict",
        ],
        input=json.dumps({"snapshot": snapshot}),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, f"opa stderr: {proc.stderr}"
    return json.loads(proc.stdout)


def test_generated_bundle_denies_mapped_v4_tool_name(tmp_path: Path) -> None:
    governance = {
        "rules": [
            {
                "name": "block-delete",
                "condition": {
                    "field": "tool_name",
                    "operator": "eq",
                    "value": "delete_file",
                },
                "action": "deny",
                "priority": 100,
                "message": "destructive tool blocked",
            }
        ],
        "intervention_points": _binding(),
    }
    (tmp_path / "governance.yaml").write_text(
        yaml.safe_dump(governance), encoding="utf-8"
    )
    manifest = resolve_manifest(
        tmp_path, tmp_path, bundle_dir=tmp_path / "generated"
    )
    bundle = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])

    denied = _evaluate(
        bundle,
        {
            "tool_call": {
                "id": "call-1",
                "name": "delete_file",
                "args": {"path": "/tmp/example"},
            }
        },
    )
    allowed = _evaluate(
        bundle,
        {
            "tool_call": {
                "id": "call-2",
                "name": "read_file",
                "args": {"path": "/tmp/example"},
            }
        },
    )

    assert denied["decision"] == "deny"
    assert denied["reason"] == "block-delete"
    assert allowed == {"decision": "allow"}


def test_generated_bundle_honours_default_deny(tmp_path: Path) -> None:
    governance = {
        "default_action": "deny",
        "rules": [],
        "intervention_points": _binding(),
    }
    (tmp_path / "governance.yaml").write_text(
        yaml.safe_dump(governance), encoding="utf-8"
    )
    manifest = resolve_manifest(
        tmp_path, tmp_path, bundle_dir=tmp_path / "generated"
    )
    bundle = Path(manifest["policies"]["agt_legacy_rules"]["bundle"])

    verdict = _evaluate(
        bundle,
        {"tool_call": {"name": "read_file", "args": {}}},
    )

    assert verdict == {"decision": "deny"}
