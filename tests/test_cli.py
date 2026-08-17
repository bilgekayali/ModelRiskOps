import json
from pathlib import Path

from modelriskops import canonical_json, sha256_digest
from modelriskops.cli import main
from tests.test_dossier import build_approved_dossier


ROOT = Path(__file__).resolve().parents[1]


def test_verify_dossier_cli_accepts_verified_bundle(tmp_path, capsys) -> None:
    dossier_path = tmp_path / "dossier.json"
    dossier_path.write_text(canonical_json(build_approved_dossier()), encoding="utf-8")
    assert main(["verify-dossier", str(dossier_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "verified"
    assert result["governance_path_complete"] is True


def test_verify_dossier_cli_rejects_tampered_bundle(tmp_path, capsys) -> None:
    payload = json.loads(canonical_json(build_approved_dossier()))
    payload["manifest_digest"] = "0" * 64
    dossier_path = tmp_path / "tampered.json"
    dossier_path.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["verify-dossier", str(dossier_path)]) == 2
    assert "error:" in capsys.readouterr().err


def test_validate_schema_cli_accepts_real_dossier(tmp_path, capsys) -> None:
    dossier_path = tmp_path / "dossier.json"
    dossier_path.write_text(canonical_json(build_approved_dossier()), encoding="utf-8")
    schema_path = ROOT / "schemas" / "governance-dossier.schema.json"
    assert main(["validate-schema", str(schema_path), str(dossier_path)]) == 0
    assert capsys.readouterr().out.strip() == "valid"


def test_digest_json_cli_uses_canonical_digest(tmp_path, capsys) -> None:
    payload = {"b": 2, "a": 1}
    path = tmp_path / "payload.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    assert main(["digest-json", str(path)]) == 0
    assert capsys.readouterr().out.strip() == sha256_digest(payload)
