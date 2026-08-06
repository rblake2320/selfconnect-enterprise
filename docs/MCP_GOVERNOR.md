# SelfConnect MCP Governor

`selfconnect-mcp-governor` is the MCP protocol boundary for the mandatory
`GovernedRuntime`. It exposes only the registered SelfConnect tool schemas and
routes every `tools/call` through `MCPDispatcher`. When configured, the
dispatcher also invokes AGT/ACS Cedar enforcement before the handler executes.

Supported protocol paths:

- MCP `2025-11-25`: `initialize`, `notifications/initialized`, `tools/list`,
  and `tools/call` over newline-delimited stdio.
- MCP `2026-07-28`: stateless `server/discover`, `tools/list`, and `tools/call`.
  Every request must carry protocol version and client capabilities in `_meta`.

The wrapper does not create an ungoverned default runtime. A deployment-owned
factory must construct and return the exact `GovernedRuntime` type:

```powershell
selfconnect-mcp-governor --factory deployment.runtime:create_runtime
```

or:

```powershell
$env:SELFCONNECT_MCP_GOVERNOR_FACTORY = "deployment.runtime:create_runtime"
selfconnect-mcp-governor
```

The protocol host is responsible for presenting tool information and obtaining
user consent. SelfConnect independently enforces signed policy, operator
approval, revocation, target validation, terminal leases, and durable audit.
Tool descriptions and self-reported MCP client metadata are never treated as
authorization evidence.

The current wrapper is stdio-only. Streamable HTTP routing headers and MRTR
approval resumption are intentionally not advertised until their transport and
durable continuation implementations are complete.
