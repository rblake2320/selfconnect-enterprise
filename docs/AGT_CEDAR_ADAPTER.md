# AGT Cedar policy adapter

SelfConnect can use Microsoft Agent Governance Toolkit's Agent Control
Specification (ACS) runtime as an additional policy gate around every MCP tool
handler. Cedar evaluation, transforms, and pre/post-tool decisions are executed
by AGT; SelfConnect does not contain a Cedar parser or evaluator.

Install the optional dependency on Python 3.11 or newer:

```powershell
python -m pip install -e ".[agt]"
```

Then pass an ACS manifest to the mandatory runtime composition:

```python
runtime = GovernedRuntime.from_signed_policy(
    # existing required SelfConnect governance arguments...
    agt_manifest_path=Path("agent-control.yaml"),
)
```

The adapter uses AGT in `enforce` mode and fails closed on import, manifest,
evaluation, transform, or result-shape errors. SelfConnect remains authoritative
for BPC/TSK identity, signed delegation, operator approval, agent revocation,
target verification, terminal injection, and the hash-chained audit ledger.
AGT is an additive policy decision layer, not an identity or execution runtime.

The integration targets the Public Preview ACS Python API
`agent-control-specification` 0.3.x (`AgentControl.from_path` and `run_tool`).
Microsoft has not published that Python distribution to PyPI, so the optional
extra pins the official repository at commit
`f4518335907fb244887053683a3d3db83613cc31` and its `policy-engine/sdk/python`
subdirectory. Advance that pin only after compatibility tests pass.
