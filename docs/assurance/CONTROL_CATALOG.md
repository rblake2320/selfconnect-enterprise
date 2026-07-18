# Executable Control Catalog

**Status:** Repository control inventory, not an authorization or compliance determination  
**Machine-readable source:** [`control_catalog.json`](control_catalog.json)

This catalog distinguishes a control from a description. Each executable entry
names its scope, assertion, expected result, evidence location, and blind spots.
Entries that require an external authority or deployment-specific ceremony are
explicitly `description` tier and cannot report `PASS` from repository tests.

Run the fast checks during ordinary work:

```powershell
python -m tools.release_conformance --tier quick
```

Run local release checks before a commit or tag:

```powershell
python -m tools.release_conformance --tier release --output conformance.json
```

`--tier live` additionally runs entries whose live dependencies are already
running. It does not start, stop, or mutate deployment services. The production
restart ceremony and external authorization/retention checks remain named
descriptions until an operator runs them against an actual boundary.

For a disposable real-Windows target demonstration, first create fresh local
identities and a signed policy with:

```powershell
python -m tools.create_conformance_fixture `
  --output-dir $env:TEMP\selfconnect-conformance `
  --require-approval
```

The generator writes only a public trust root, signed policy, non-secret
manifest, and DPAPI-protected identities. Run `tools.irs_runtime_conformance`
with an inspected target HWND and the generated paths. The operator must type
the exact approval phrase when execution is requested and provide an explicit
`--test-only-operator-proof`; that local verifier is conformance-only and is not
a production operator identity. Without an explicit proof, an approval-required
execution fails closed. A full `PASS` also
requires `--expect-output`; that token must be absent from `--text` and must
newly appear after the command executes. An `--execute` run without an effect
token is delivery evidence only and returns `PARTIAL`.

## Status Semantics

| Status | Meaning |
|---|---|
| `PASS` | The named executable assertion returned its expected process result in this run. |
| `FAIL` | The assertion ran and failed. |
| `NOT_RUN` | The entry is above the selected tier. |
| `DESCRIPTION` | The item needs deployment or external-authority evidence and cannot pass from repository code. |

A `PASS` never expands beyond the entry's scope. Blind spots are part of the
control contract, not optional commentary.

## Change Rule

A new security, durability, classification, or authorization-support claim must
either map to an existing catalog entry or add/update an entry in the same
change. A missing assertion means the item is a description. New components
must name cross-repository and runtime blind spots explicitly.
