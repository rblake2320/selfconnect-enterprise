# Product Scope Boundary

Decision date: 2026-07-31

## What SelfConnect takes from Buzz

Buzz publicly documents three useful identity/access semantics:

- An agent has its own public key and profile, separate from the human or
  organization operating it.
- Authentication proves key possession; authorization is evaluated separately.
- Community owners can remove principals from community access, and channel
  membership gates read/write access.

SelfConnect adopts the first two ideas and the lifecycle principle behind the
third: remove the compromised agent principal without replacing the human
owner. SelfConnect does not adopt membership as its only authorization model.
Its signed delegation, policy, approval, classification, target, replay,
revocation, and audit controls remain authoritative.

The reviewed public Buzz documentation does not establish a global,
monotonic, cross-workspace agent/grant revocation service equivalent to
`RevocationRegistry`. The comparison should therefore say “separate agent
identity and access removal,” not claim implementation equivalence.

## Explicitly excluded

SelfConnect Enterprise will not build or absorb Buzz's collaboration-product
surface:

- workspace/community UI;
- channels, threads, direct messages, reactions, or presence;
- canvases, media rooms, or huddles;
- forge, repository hosting, patch review, or merge workflows;
- Git object storage, issue tracking, CI orchestration, or release management;
- social discovery, profiles, reputation, or community moderation UI.

These are not roadmap gaps. They are deliberate exclusions. ACP clients and
Nostr-shaped evidence export provide interoperability at the boundaries while
SelfConnect stays focused on governed execution through the operating-system
terminal medium.

## Reconsideration rule

Reconsider an excluded surface only when a named regulated deployment requires
it as an enforcement dependency that cannot remain in an external system. A
general desire for product breadth, parity, or workspace convenience is not
sufficient.

## Primary sources

- [Buzz security design](https://github.com/block/buzz/security)
- [Buzz support and agent identity](https://block.github.io/buzz/support.html)
- [Buzz README capability table](https://github.com/block/buzz#works-today--being-wired-up--strong-opinions-pending-code)
