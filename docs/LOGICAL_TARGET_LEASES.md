# Logical Target Leases

`LogicalTargetResolver` gives a trusted MCP host stable local names for terminal
windows without weakening the existing target guard or lease authority.

The host constructs immutable `LogicalTargetSpec` values at startup and injects
the resolver into `MCPDispatcher`. Each specification requires an exact local
drive-letter absolute executable path with no surrounding whitespace, a
non-empty window class without ASCII control characters, title SHA-256, and closed set of lease roles.
There are no built-in product, browser, file, or government targets.

`sc_request_target_lease` performs this sequence:

1. Reject an unknown logical ID or unauthorized role before window discovery.
2. Enumerate a bounded snapshot of top-level HWNDs.
3. Run every candidate through the dispatcher's canonical target verifier with
   the complete configured selector.
4. Deny zero matches, multiple matches, incomplete reports, or mismatched
   successful reports.
5. Capture the unique live PID, executable path, class, and title hash in the
   existing signed `RuntimeLease`, including the logical ID.

Actuation still requires the raw HWND from the issued lease. The dispatcher and
router recheck the captured identity before input, so HWND reuse or target
replacement after alias resolution denies before mutation.

## Boundary

This is process-local trusted-startup configuration and terminal discovery. It
does not persist aliases or leases across restart, authorize runtime alias
registration, route by classification, support browser/file targets, add new
executor actions, or make Win32 discovery and later actuation atomic. Unit tests
use injected enumerators and verifier reports as contract evidence; they are not
live-desktop proof.
