# prompt-injection-checkout-guard

![Node >=20](https://img.shields.io/badge/node-%3E%3D20-339933.svg) ![Zero Dependencies](https://img.shields.io/badge/dependencies-0-10b981.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Red-team exploit test harness and deterministic zero-trust guardrail protecting AI shopping and checkout agents from prompt injection, tool hijacking, and price tampering.

## Why prompt filters alone fail

Relying only on a system prompt (`"Never give discounts"`) or a regex classifier fails the moment an attacker rephrases the attack in another language, encodes Unicode bidi controls, or slips an extra field into a tool call.

This kit separates defense into five independent layers so that **even if a novel phrasing gets past prompt scanning, the LLM still has zero technical ability to alter unit prices or call privileged write tools**:

1. **Tool Allowlist:** Only read-safe catalog lookups and `create_checkout_intent` are exposed. Tools like `apply_discount` or `update_price` are rejected at the gateway (`403`).
2. **Smuggled-Field Rejection:** Any tool argument containing `price`, `unit_price`, `total`, or `discountPercent` fails closed (`400`).
3. **Strict Schema Validation:** Only `sku`, bounded integer `quantity` (`1..50`), and optional `couponCode` are accepted.
4. **Server-Authoritative Catalog Pricing:** The server computes `subtotal` and `finalTotal` strictly from the database catalog and enforces a hard coupon cap.
5. **Injection Telemetry Scanner:** Detects delimiter escapes, role escalations, Unicode bidi smuggling, tool-call syntax, and secret exfiltration attempts.

## Architecture

```mermaid
flowchart TD
    U["Untrusted Buyer Prompt"] --> L["LLM Agent (Untrusted Output)"]
    L --> G1{"Layer 1: Allowed Tool?"}
    G1 -- "apply_discount / update_price" --> B1["403 Blocked"]
    G1 -- "create_checkout_intent" --> G2{"Layer 2: Smuggled Price Field?"}
    G2 -- "unit_price / total present" --> B2["400 Rejected"]
    G2 -- "SKU + Qty only" --> G3["Layer 3-4: Server Catalog Price Lookup"]
    G3 --> G4{"Layer 5: Injection Scan Clean?"}
    G4 -- "Flagged" --> B3["403 Blocked + Telemetry"]
    G4 -- "Clean" --> OK["201 Server-Locked Order Created"]
```

## Quick Start

```bash
git clone https://github.com/JARMID/prompt-injection-checkout-guard.git
cd prompt-injection-checkout-guard
npm test
```

## License

MIT © [Khalef Abdelmadjid (@JARMID)](https://github.com/JARMID)
