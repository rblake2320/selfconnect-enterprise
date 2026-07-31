# ACP and Governance Positioning

Evidence date: 2026-07-31

## Defensible position

SelfConnect's differentiation is not ACP transport by itself. It is the
governed path behind that transport:

```text
ACP ecosystem client
  -> owner authorization + agent authorship
  -> live revocation + replay denial
  -> policy + operator approval + target revalidation
  -> terminal-as-medium injection
  -> signed, chained evidence
```

Within the products and public materials reviewed for this decision, no other
implementation demonstrated this same end-to-end terminal-as-medium
enforcement chain. That is a bounded landscape finding, not proof of uniqueness
across every private, unpublished, or future system.

## Current Buzz opening

Block's public Buzz README currently lists its ACP harness as working while
placing “Workflow approval gates” in its “Being wired up” column and describing
the infrastructure as present but the integration as unfinished. This creates
a present shipped-versus-in-progress opening for SelfConnect's governed
execution layer.

The comparison must remain time-stamped. Buzz can close that implementation
gap, and its signed event/audit architecture should not be described as absent.
SelfConnect's durable claim should therefore be its composed enforcement path,
not a permanent assertion that a named competitor lacks approvals.

## Executable evidence

`test_acp_cannot_bypass_governed_operator_approval` constructs the canonical
`GovernedRuntime` from a real signed policy that requires approval, creates a
valid owner delegation and agent action proof, and submits the exact signed
injection through ACP without an approval. The governed runtime denies it, ACP
returns a backend rejection, the terminal router receives no text, and the
action ID remains consumed to prevent an unsafe blind retry.

The same composition test then creates a signed, exact-context operator
approval and submits a second agent-signed ACP action. Only that approved text
reaches the deterministic terminal router, and the returned governance receipt
reports `human_approved`. Together the two paths prove both fail-closed denial
and authorized completion through the same production boundary.

An adversarial third path approves one text value, then submits a different,
otherwise-valid agent-signed ACP payload carrying that approval ID. Exact
approval-context verification rejects the substitution, routes no additional
terminal text, and consumes the attempted action ID.

## Messaging guardrails

- Say: “Differentiated across the reviewed public implementations as of
  2026-07-31.”
- Say: “ACP brings ecosystem clients to SelfConnect's governed execution
  boundary.”
- Say: “Buzz publicly describes workflow approval gates as still being wired
  up as of the evidence date.”
- Do not say: “Unique across the entire market” without a dated, reproducible
  market review.
- Do not imply ACP replaces terminal injection, BPC/TSK, policy, approval,
  target validation, or signed audit.
- Do not position SelfConnect as a Buzz workspace, forge, Git host, channel
  system, or collaboration-suite competitor. Those layers are explicitly
  excluded; SelfConnect is the governed execution substrate beneath clients.

## Primary source

- Block Buzz README, `Works today / Being wired up` table:
  <https://github.com/block/buzz#works-today--being-wired-up--strong-opinions-pending-code>
