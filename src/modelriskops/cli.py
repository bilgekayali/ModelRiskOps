from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import jsonschema

from .api import __all__ as STABLE_API_SYMBOLS
from .canonical import sha256_digest
from .dossier import dossier_from_dict
from .models import GovernanceError

RELEASE_VERSION = "1.0.0"
STABLE_CLI_COMMANDS = ("contract-snapshot", "digest-json", "validate-schema", "verify-dossier")


def _load_json(path: str) -> object:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GovernanceError(f"unable to read valid JSON from {path}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="modelriskops",
        description="ModelRiskOps deterministic governance evidence utilities",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    snapshot = sub.add_parser("contract-snapshot", help="print the deterministic v1 stable public-contract snapshot")
    snapshot.set_defaults(_stable_command=True)

    digest = sub.add_parser("digest-json", help="print the canonical SHA-256 digest of a JSON document")
    digest.add_argument("document")

    schema = sub.add_parser("validate-schema", help="validate a JSON document against a Draft 2020-12 schema")
    schema.add_argument("schema")
    schema.add_argument("document")

    verify = sub.add_parser("verify-dossier", help="verify a self-contained ModelRiskOps governance dossier offline")
    verify.add_argument("dossier")

    return parser


def contract_snapshot() -> dict[str, object]:
    return {
        "release_version": RELEASE_VERSION,
        "compatibility_series": "v1",
        "python_api_symbols": sorted(STABLE_API_SYMBOLS),
        "cli_commands": list(STABLE_CLI_COMMANDS),
        "execution_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "contract-snapshot":
            print(json.dumps(contract_snapshot(), sort_keys=True, separators=(",", ":")))
            return 0

        if args.command == "digest-json":
            payload = _load_json(args.document)
            print(sha256_digest(payload))
            return 0

        if args.command == "validate-schema":
            schema_payload = _load_json(args.schema)
            document_payload = _load_json(args.document)
            if not isinstance(schema_payload, dict):
                raise GovernanceError("schema document must be a JSON object")
            jsonschema.Draft202012Validator.check_schema(schema_payload)
            jsonschema.Draft202012Validator(schema_payload).validate(document_payload)
            print("valid")
            return 0

        if args.command == "verify-dossier":
            payload = _load_json(args.dossier)
            if not isinstance(payload, dict):
                raise GovernanceError("dossier document must be a JSON object")
            dossier = dossier_from_dict(payload)
            print(
                json.dumps(
                    {
                        "status": "verified",
                        "manifest_digest": dossier.manifest_digest,
                        "governance_state": dossier.governance_state.value,
                        "governance_path_complete": dossier.governance_path_complete,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0

        raise GovernanceError("unsupported command")
    except (GovernanceError, jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
