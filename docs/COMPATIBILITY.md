# ModelRiskOps v1 Compatibility Policy

ModelRiskOps `1.x` introduces an explicit stable compatibility boundary. Stability is intentionally narrower than the set of importable implementation modules.

## Stable Python API

Only symbols exported by `modelriskops.api` are covered by the v1 Python API compatibility contract. The root `modelriskops` package and internal modules remain importable for compatibility with earlier releases, but they are not promoted to the stable v1 API unless they are re-exported from `modelriskops.api`.

`compatibility/v1-public-api.json` is the machine-readable baseline. Removal of a stable Python symbol requires a new major version.

## Stable CLI

The v1 stable CLI commands are:

- `contract-snapshot`
- `digest-json`
- `validate-schema`
- `verify-dossier`

Removal of a stable CLI command requires a new major version. `contract-snapshot` prints a deterministic, non-executing description of the stable Python and CLI surface.

## JSON schemas

`compatibility/v1-schema-baseline.json` freezes the complete schema file set present at the v1 baseline. The stable release gate requires the current `schemas/*.schema.json` file set to match that baseline exactly.

Within the 1.x compatibility series, removing a baseline schema, removing a required field, or removing an existing enum value is treated as a breaking change and requires a new major version. Unknown fields remain rejected where the schema declares `additionalProperties: false`.

Additive schema changes must still preserve existing valid documents and contract semantics. A change that is syntactically additive but alters authorization, validation, risk, review, cryptographic, tenant-isolation, release, or non-claim semantics is not automatically considered compatible.

## SemVer and deprecation

ModelRiskOps uses Semantic Versioning for the declared stable surface. The v1 contract requires at least two minor releases of deprecation before a stable surface is removed in a later major transition, except where an immediate security fix is necessary to prevent unsafe behavior.

Security fixes take precedence over preserving behavior that would knowingly retain an unsafe control bypass. Such cases must be documented explicitly.
