# Aegis Social Platform — Product Specification v2
## Project Aegis · WCNegentropy Holdings LLC

> **Document Type:** Product & Architecture Specification
> **Version:** 2.2
> **Date:** 2026-04-21
> **Status:** Active — aligned to `Aegis_OS_Browser_Plan.md` as the repo-grounded sequencing source of truth
> **Repo:** [WCNegentropy/PQC-Layer-Project](https://github.com/WCNegentropy/PQC-Layer-Project)

---

## Executive Summary

The Aegis Social Platform is a decentralized, post-quantum-cryptographically secured social environment built natively on the Aegis infrastructure stack. It is best understood as a spiritual successor to the creative era of MySpace and the playful world-building of Club Penguin — rebuilt from first principles with 2026-era cryptography, true data ownership, and a free-by-default economic model that is structurally impossible for centralized competitors to replicate.

Every user gets their own **private node** and **Personal Space**: a fully customizable, HTML/CSS/JS-rendered digital environment stored entirely in their local Aegis encrypted vault and served from infrastructure they control. Characters, outfits, items, room layouts, and profile data are all local-first JSON and asset files — the platform hosts nothing on their behalf by default. Social interaction happens directly private-node-to-private-node over PQC-secured Aegis tunnels, or via **opt-in** shared Sanctuary nodes for group spaces and events. Because content lives on user devices, the core platform is **free by default** — not as a promotional offer, but as a structural consequence of the architecture.

In current repo terms, that vision is **not** greenfield. The implemented base is the crypto layer, gateway transport, Sanctuary server primitive, and identity/vault foundations. The desktop app, web app, and full social runtime are still mostly placeholders or planned work, so the delivery sequence is:

1. harden identity + vault into a real private-node substrate,
2. turn `aegis-desktop` into the **Aegis Browser / runtime shell**,
3. add direct visits, sync, messaging, and optional shared nodes,
4. only later package the mature runtime as AegisOS.

## Network Topology Thesis

The intended default path is:

```text
User A private node ──► User B private node
```

Not:

```text
User A ──► platform Sanctuary ──► User B
```

Shared Sanctuary nodes still matter, but only as optional spaces a user chooses to join or host:

```text
User A private node ──► shared Sanctuary / community node
```

This means:

- the core product does not require WCNegentropy-hosted servers to function,
- local testing can prove the architecture with two private nodes on one machine,
- shared nodes are additive social spaces rather than central dependencies,
- discovery is the main additional systems problem, not content hosting.

---

## The Core Thesis: Free By Default Is Architectural, Not Promotional

On every centralized social platform, "free" means the user is the product. Storage, compute, CDN delivery, and database queries all cost money — so the platform monetizes attention and data to cover those costs.

On the Aegis Social Platform, the cost equation is inverted:

- **Your room** is served from your device, not a CDN.
- **Your items** are files in your vault, not rows in a database.
- **Your character** is a JSON file you own, not a record tied to an account you could lose.
- **Your messages** are end-to-end encrypted before they leave your device.
- **Your node** is yours to run — the platform does not need to host your room for you.

There is no central infrastructure bill for user content because there is no central infrastructure serving it. This means the free tier is not subsidized — it is simply the natural state of the system. Paid extras exist, but they are genuinely optional enhancements, not paywalled core features.

---

## Platform Layers

### Layer 1 — Personal Space (The Room)

Every user's digital home. Stored entirely in the user's Aegis vault under `vault://social/space/`.

**What it is:**
- A directory of HTML, CSS, JS, JSON, and asset files that render the user's personal environment
- Fully customizable — users can hand-code their entire space or use provided editors/themes
- Rendered locally in the Aegis desktop/mobile app's built-in sandboxed browser context
- Served to visiting peers directly over a PQC tunnel — no intermediary

**Vault directory structure:**
```
vault://social/
├── space/
│   ├── index.html          # The room itself — fully user-editable
│   ├── style.css           # Custom styling
│   ├── room.json           # Room metadata: name, description, theme, layout
│   └── assets/             # Images, sounds, custom item sprites
├── character/
│   ├── avatar.json         # Character definition
│   ├── equipped.json       # Currently equipped outfit/items
│   └── assets/             # Avatar sprite sheets, custom overlays
├── inventory/
│   └── inventory.json      # All owned items with VC proofs
├── profile/
│   └── profile.json        # Display name, bio, DID, social links
└── feed/
    └── posts.json          # User's own post history (ActivityPub objects)
```

**Custom coding:**
Users have full access to edit `index.html`, `style.css`, and any supporting JS. The rendering sandbox enforces security (no external fetch, no access to vault internals outside `vault://social/space/assets/`) but places zero creative restrictions. This is the MySpace HTML injection era reborn — with actual ownership and without the XSS.

---

### Layer 2 — Character & Identity

The user's in-world presence. Separate from their cryptographic DID identity (Layer 4 of Aegis) but linked to it.

**`avatar.json` schema:**
```json
{
  "schema_version": "1.0",
  "did": "did:aegis:z6Mk...",
  "display_name": "NebulaFox",
  "base_sprite": "humanoid_v1",
  "skin_tone": "#F5CBA7",
  "equipped": {
    "head": "item:galaxy-helmet-001",
    "body": "item:neon-jacket-042",
    "feet": "item:hover-boots-007",
    "background": "item:deep-space-bg-003",
    "accessory": null
  },
  "custom_sprite_override": null,
  "created_at": "2026-04-17T00:00:00Z"
}
```

The `did` field links the character to the user's Aegis DID — when another user visits your space or sees your character in a shared node, they can cryptographically verify that the character belongs to the DID they connected to. Impersonation is structurally impossible.

---

### Layer 3 — Items & Digital Ownership

Items are JSON-defined objects with optional asset files (sprites, sounds, scripts). Every item has a **Verifiable Credential** issued by either the platform or a trusted creator, stored alongside it in the vault.

**`inventory.json` schema:**
```json
{
  "schema_version": "1.0",
  "owner_did": "did:aegis:z6Mk...",
  "items": [
    {
      "item_id": "item:galaxy-helmet-001",
      "name": "Galaxy Helmet",
      "type": "wearable/head",
      "rarity": "rare",
      "sprite": "assets/items/galaxy-helmet-001.png",
      "acquired": "2026-04-17T00:00:00Z",
      "source": "platform:launch-event",
      "transferable": true,
      "vc_proof": {
        "type": "ML-DSA-65",
        "issuer": "did:aegis:platform-issuer",
        "issued_at": "2026-04-17T00:00:00Z",
        "signature": "..."
      }
    }
  ]
}
```

**Why this solves the NFT problem:**

NFTs promised digital ownership but delivered JPEG URLs on centralized servers. When OpenSea goes down or deletes a listing, the "owned" asset becomes a broken link. In Aegis:

- The item file lives **in your encrypted vault** on your device
- Ownership is proven by the **ML-DSA-65 VC signature**, not by a blockchain entry
- The platform cannot revoke your item by taking down a server — it would have to break your cryptographic proof
- Items can be transferred peer-to-peer over PQC tunnels with a simple VC re-issuance — no gas fees, no smart contract, no blockchain required

**Item creation:** Any user or creator can define new items. The format is open. Community-created items are signed by the creator's DID rather than the platform issuer — wallets and inventory views display the issuer so users can assess trust.

---

### Layer 4 — Visiting & Peer-to-Peer Space Rendering

When User A visits User B's space:

1. User A's client resolves User B's private node via manual exchange, bootstrap discovery, or DID records
2. User A's client initiates a PQC tunnel directly to User B's Aegis node
3. User B's client serves `vault://social/space/` over the authenticated, encrypted tunnel
4. User A's client renders the received HTML/CSS/JS in a sandboxed local context
5. User A's character (avatar JSON + equipped items) is transmitted to User B's client for rendering in B's space
6. Real-time interaction (chat, emotes, positional state) is handled via PQ Double Ratchet messaging over the same tunnel

**Privacy properties of a visit:**
- The visit content (room HTML) is encrypted in transit (ChaCha20-Poly1305)
- User B can verify User A's DID before serving content (whitelist/blocklist supported)
- No platform server sees the room content or the visit — it is a direct private-node connection
- User B can revoke access at any time by closing the tunnel

---

### Layer 5 — Shared Nodes (The Club Penguin Room Analogy)

Shared nodes are **opt-in** Sanctuary-compatible environments that multiple users visit simultaneously — the closest equivalent to Club Penguin's public rooms or a virtual event space.

**How they work:**
- A shared node is an Aegis Sanctuary-compatible instance running a **room server** crate (`aegis-social` Layer 7)
- The room's state is a **CRDT-synced JSON document** — all connected clients maintain a consistent view of who is present, where characters are positioned, and what the current room state is
- Group messaging within a shared node uses **MLS (Messaging Layer Security)** with ML-KEM-768 — all chat is end-to-end encrypted even on a shared node the platform operates
- The room's visual environment (HTML/assets) is served by the node operator — platform-hosted nodes are optional, community-hosted nodes can provide anything

**Node types:**

| Node Type | Operator | Content | Cost |
|---|---|---|---|
| Platform Official | WCNegentropy | Curated environments, events | Free to attend |
| Community Node | Any user with Sanctuary | Custom room HTML/assets | Free to host (self-hosted) |
| Creator Node | Verified creator | Branded environments | Free or ticketed |
| Private Node | Any user | Invite-only group space | Free (self-hosted) |

**Shared node state document (`room-state.json` — CRDT):**
```json
{
  "room_id": "node:platform:town-square-01",
  "present_users": [
    {
      "did": "did:aegis:z6Mk...",
      "display_name": "NebulaFox",
      "position": { "x": 340, "y": 210 },
      "equipped": "vault://character/equipped.json (hash: ...)"
    }
  ],
  "room_events": [],
  "last_updated": "2026-04-17T00:36:00Z"
}
```

---

### Layer 6 — Messaging

All messaging is post-quantum encrypted, natively integrated with the Aegis crypto stack.

| Message Type | Protocol | Encryption | Forward Secrecy |
|---|---|---|---|
| Direct Message (1:1) | PQ Double Ratchet | ML-KEM-768 + ChaCha20-Poly1305 | ✅ Per-message |
| Space Chat (visitor in your room) | PQ Double Ratchet | Same as DM | ✅ Per-session |
| Shared Node Group Chat | MLS (RFC 9420) + ML-KEM-768 | Group key agreement | ✅ Per-epoch |
| Async Message (offline) | Optional deferred delivery via user/community/platform-operated relay node | ML-KEM-768 encrypted to recipient PK | ✅ |

Messages are stored in the user's vault, not on any server. Direct delivery between private nodes is the default. If offline delivery is later added, relay/store-and-forward infrastructure must remain optional and ciphertext-only — not a prerequisite for the core experience.

---

### Layer 7 — Federation (ActivityPub)

The Aegis Social Platform is natively federated via ActivityPub, with all federated messages signed using ML-DSA-65.

- User DIDs double as ActivityPub actor identifiers
- Posts published to a user's feed are ActivityPub `Note` objects, signed by the user's ML-DSA-65 key
- Users can follow and be followed by accounts on any ActivityPub-compatible server (Mastodon, Misskey, Pixelfed, etc.)
- Federated interactions are delivered to the user's vault feed, not a centralized inbox

This means the Aegis Social Platform launches with access to the entire Fediverse — tens of millions of existing users — on day one, without needing to build a cold-start network from scratch.

---

## Economic Model

### Free By Default — Everything Core

| Feature | Cost | Reason |
|---|---|---|
| Personal Space (HTML/CSS/JS room) | Free forever | Lives in user's vault — no hosting cost |
| Private node runtime | Free forever | Core user-owned infrastructure |
| Character + base avatar | Free forever | Local JSON file |
| Base item set (launch collection) | Free forever | Distributed as vault-importable bundles |
| Custom-coded space | Free forever | User's own compute, user's own vault |
| Visiting other spaces | Free forever | Direct node-to-node tunnel — no CDN cost |
| Attending shared nodes | Free forever | Node operator bears cost, not platform |
| Direct messaging | Free forever | PQC tunnel, vault storage |
| ActivityPub federation | Free forever | Standard protocol, no per-message cost |
| Self-hosting a shared node | Free forever | User runs their own node |

### Paid Extras — Genuinely Optional

| Feature | Model | Notes |
|---|---|---|
| Premium item drops | One-time purchase | Exclusive cosmetics, rare collectibles |
| Creator marketplace | Revenue share | Creators sell item bundles, room themes |
| Premium official room/theme packs | One-time purchase | User-importable content they keep |
| Verified creator badge | One-time fee | DID-linked, ML-DSA-65 signed by platform |
| Optional managed services (if offered later) | Service fee | Convenience only, never required for core access |

The guiding principle: **if it is core to user sovereignty, it is free and user-controlled. Paid extras should be optional, ownership-preserving, and preferably one-time rather than recurring.**

---

## Competitive Differentiation

| Platform | Data ownership | E2E encrypted | PQC | Customizable | Free core |
|---|---|---|---|---|---|
| **Aegis Social** | ✅ Full (vault) | ✅ All comms | ✅ Native | ✅ Full HTML/JS | ✅ Structural |
| Meta (FB/IG) | ❌ Platform owns | ❌ | ❌ | ❌ | ❌ (data = product) |
| Twitter/X | ❌ Platform owns | ❌ | ❌ | ❌ | ❌ |
| Mastodon | ⚠️ Server-dependent | ❌ | ❌ | ❌ | ✅ |
| Signal | ✅ E2E | ✅ | ❌ | ❌ | ✅ |
| Secria | ⚠️ Email only | ✅ Email | ✅ Email | ❌ | ❌ |

---

## Implementation Roadmap

### Phase 1 Complete
- ✅ `aegis-crypto`, `aegis-gateway`, and `aegis-sanctuary` are implemented and usable foundations
- ✅ CLI bootstrap flows exist for identity creation and vault initialization
- ✅ The repo already proves the seed of a private-node bootstrap path: create identity → create vault → populate social layout

### Canonical Runtime Roles
- **`aegis-desktop`** = future Aegis Browser / runtime shell
- **`aegis-cli`** = bootstrap, ops, and diagnostics tool
- **`aegis-web`** = auxiliary status/API/web surface, not the primary sovereign runtime
- **`aegis-sanctuary`** = optional private/shared-node transport primitive, not a mandatory central platform hop

### Phase 2A — Identity Foundation (prerequisite)
- ✅ Implemented foundational `aegis-identity` support: local `did:aegis` generation, root→device identity issuance, ML-DSA-65 VC issuance/verification, and signed auth challenges
- ✅ Implemented foundational `aegis-vault` support: per-file AEAD encryption and bootstrap creation of the social vault directory structure
- ✅ Implemented Linux-first virtual vault mount support: read-only/read-write projection, explicit refresh/sync, sync-back on unmount, and plaintext cleanup
- ✅ Implemented local DID/service-record support for manual private-node discovery bootstrap
- ✅ Added CLI commands: `aegis vault init`, `aegis identity new`, `aegis identity show`
- ⏳ Still planned for later in Phase 2A: full CRDT sync engine, recovery flows, multi-node loopback proof, and cross-platform/native mount backends beyond the current Linux-first virtual projection

### Phase 2B — Social Core
- Implement `aegis-social` crate:
  - Private node runtime enabled by default for each user
  - Space server: serve `vault://social/space/` over authenticated PQC tunnel
  - Space client: render received space HTML in sandboxed context
  - Character sync: transmit equipped avatar JSON to visiting peers
  - Item VC verification: validate inventory proofs on receipt
  - Local two-node loopback testing on one machine as the first full-system proof
- Turn the placeholder Tauri desktop app (`aegis-desktop`) into the Aegis Browser / runtime shell:
  - space viewer/editor
  - character panel
  - inventory manager
  - identity/vault management UI
  - local protocol handling for `vault://`, `node://`, and `sanctuary://`

### Phase 2C — Shared Nodes & Messaging
- Manual peer exchange for MVP discovery
- Shared node room server: CRDT state sync, MLS group messaging
- Bootstrap discovery nodes outside the normal content path
- PQ Double Ratchet DM implementation
- Optional async/deferred delivery relay model
- Sanctuary node operator tooling for community-hosted rooms

### Phase 2D — Federation & Ecosystem
- ActivityPub actor implementation tied to DID
- ML-DSA-65 signed AP object publishing
- Creator tools: item bundle format, room theme packaging, marketplace protocol
- Auxiliary `aegis-web` service/API surface
- Mobile app (`aegis-mobile`): iOS and Android space viewer
- Optional immutable AegisOS packaging after the runtime stack is mature

---

## Aegis Layer Mapping

| Social Feature | Aegis Layer | Crate | Status |
|---|---|---|---|
| PQC tunnel foundation for direct space visits | Layer 3 | `aegis-gateway` | ✅ Implemented |
| Sanctuary-compatible responder/server primitive | Layer 3 | `aegis-sanctuary` | ✅ Implemented |
| Hybrid KEM, AEAD, ML-DSA-65 | Layer 2 | `aegis-crypto` | ✅ Implemented |
| DID identity + node discovery + VC item proofs | Layer 4 | `aegis-identity` | 🟡 Foundation implemented |
| Vault storage for all social data | Layer 5 | `aegis-vault` | 🟡 Foundation implemented |
| Aegis Browser / runtime shell | Layer 6 | `aegis-desktop` | 🟧 Placeholder |
| Auxiliary service/API/web surface | Layer 6 | `aegis-web` | 🟧 Placeholder |
| Private node runtime, shared nodes, AP feed | Layer 7 | `aegis-social` | 🔲 Planned |

---

## Threat Model

### What the platform protects against:
- **Platform surveillance:** All content is in user vaults — the platform cannot read rooms, items, or messages
- **Mass data breach:** No central database of user content to breach
- **Harvest-now-decrypt-later attacks:** ML-KEM-768 + X25519 hybrid KEM renders future quantum decryption of intercepted traffic infeasible
- **Identity impersonation:** DID-linked characters with ML-DSA-65 signatures make spoofing cryptographically detectable
- **Asset rug-pulls:** Items stored in user vault with VC proofs — no server to take down
- **Platform lock-in:** HTML, JSON, and user data remain user owned and locally controlled

### What the platform does not protect against:
- **Compromised user device:** If the device is compromised, vault contents are at risk — mitigated by hardware keyring integration (TPM/Secure Enclave, planned)
- **Malicious room code:** Custom HTML/JS is sandboxed but users should treat visited spaces like websites — exercise the same caution
- **Bad discovery information:** Bootstrap/manual discovery can be wrong until verified against identity material
- **Shared node operator visibility:** The operator of a shared node can see who is connected (by DID) and room-level interaction metadata, though not message content (MLS encrypted)
- **Physical access attacks:** The vault passphrase and device PIN are the last lines of defense if the device is physically seized

---

## Summary

The Aegis Social Platform is the consumer-facing expression of the Aegis infrastructure, but the repo-grounded sequence matters: the transport layer exists today, identity/vault foundations exist today, and the private-node social runtime plus Aegis Browser remain the intended next architecture. The immediate product goal is a real private-node substrate and trusted browser/runtime shell; AegisOS is a later packaging and hardening outcome, not the first deliverable.
