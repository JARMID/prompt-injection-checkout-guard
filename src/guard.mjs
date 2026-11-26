/**
 * Zero-Trust Server-Side Checkout Guardrail for LLM Shopping Agents
 * -----------------------------------------------------------------
 * Core principle: Treat EVERY user message AND EVERY LLM tool-call output
 * as untrusted input. Never let an LLM read or mutate unit prices,
 * override discount rules, or invoke privileged backend tools.
 */

export const INJECTION_PATTERNS = [
  { id: "ignore_instructions", rx: /\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|system|all|above)\b.{0,30}\b(instruction|prompt|rule|policy)/i },
  { id: "role_escalation", rx: /\b(you are now|act as|switch to|enter)\b.{0,30}\b(admin|developer|root|system|debug|qa|maintenance|pricing)\b/i },
  { id: "direct_price_override", rx: /\b(set|change|update|force|override)\b.{0,25}\b(price|total|amount|cost|subtotal)\b.{0,20}\b(to|=|:)?\s*(0|1|\$?0\.01|1\s*da|free)/i },
  { id: "unbounded_discount", rx: /\b(99%|100%|99\.9%|unlimited|admin|vip|internal)\b.{0,25}\b(discount|coupon|promo|voucher|off)\b/i },
  { id: "tool_smuggling", rx: /\b(apply_discount|update_price|set_price|bypass_payment|create_admin_order|exec_sql)\s*\(/i },
  { id: "delimiter_escape", rx: /(<\s*\/?\s*system\s*>|\[\/?SYSTEM\]|###\s*SYSTEM\s*OVERRIDE|BEGIN\s+SYSTEM\s+PROMPT)/i },
  { id: "hidden_unicode_bidi", rx: /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/ },
  { id: "secret_exfiltration", rx: /\b(reveal|print|dump|output|show)\b.{0,30}\b(system prompt|api key|secret|env|database|password|token)\b/i },
];

const ALLOWED_AGENT_TOOLS = new Set(["lookup_catalog_item", "create_checkout_intent"]);

/**
 * Normalize homoglyphs/control chars and scan untrusted buyer text for prompt injection.
 */
export function scanPromptInjection(userText) {
  const raw = String(userText || "");
  const matched = [];
  for (const rule of INJECTION_PATTERNS) {
    if (rule.rx.test(raw)) {
      matched.push(rule.id);
    }
  }
  return {
    flagged: matched.length > 0,
    matchedRules: matched,
    riskScore: Math.min(100, matched.length * 45),
  };
}

/**
 * Validate an LLM-proposed tool call against strict least-privilege allowlists
 * and server-authoritative catalog pricing.
 *
 * Notice: Even if an attacker bypasses regex detection with novel phrasing,
 * the deterministic server-side price lock STILL prevents any price tampering
 * because `unit_price`, `total`, and arbitrary discounts from the LLM are ignored.
 */
export function executeGuardedCheckout({
  userMessage,
  llmToolCall,
  catalog,
  coupons = {},
}) {
  const scan = scanPromptInjection(userMessage);

  // Layer 1: Reject disallowed or privileged tool names unconditionally
  const toolName = String(llmToolCall?.tool || "");
  if (!ALLOWED_AGENT_TOOLS.has(toolName)) {
    return {
      ok: false,
      status: 403,
      reason: "forbidden_tool_invocation",
      toolName,
      injectionScan: scan,
    };
  }

  // Layer 2: Reject payloads that attempt to smuggle price or total fields
  const args = llmToolCall?.arguments || {};
  const forbiddenKeys = ["unitPrice", "unit_price", "price", "total", "overridePrice", "discountPercent", "isAdmin"];
  const smuggled = forbiddenKeys.filter((k) => Object.prototype.hasOwnProperty.call(args, k));
  if (smuggled.length > 0) {
    return {
      ok: false,
      status: 400,
      reason: "client_price_tampering_rejected",
      smuggledFields: smuggled,
      injectionScan: scan,
    };
  }

  // Layer 3: Strict schema validation (SKU + positive bounded quantity only)
  const sku = String(args.sku || "").trim().toUpperCase();
  const quantity = Number(args.quantity);
  if (!sku || !Number.isInteger(quantity) || quantity < 1 || quantity > 50) {
    return {
      ok: false,
      status: 400,
      reason: "invalid_sku_or_quantity",
      injectionScan: scan,
    };
  }

  const product = catalog[sku];
  if (!product) {
    return { ok: false, status: 404, reason: "sku_not_found", injectionScan: scan };
  }

  // Layer 4: Server-authoritative pricing & bounded coupon verification
  let discountMinor = 0;
  let appliedCoupon = null;
  if (args.couponCode) {
    const code = String(args.couponCode).trim().toUpperCase();
    const coupon = coupons[code];
    if (!coupon || !coupon.active) {
      return { ok: false, status: 422, reason: "invalid_or_inactive_coupon", injectionScan: scan };
    }
    const maxAllowedPct = Math.min(coupon.percentOff, 30); // Hard policy ceiling: 30% max
    discountMinor = Math.floor((product.priceMinor * quantity * maxAllowedPct) / 100);
    appliedCoupon = code;
  }

  const subtotalMinor = product.priceMinor * quantity;
  const finalTotalMinor = subtotalMinor - discountMinor;

  // Layer 5: Block checkout creation if active prompt injection was detected
  if (scan.flagged) {
    return {
      ok: false,
      status: 403,
      reason: "prompt_injection_blocked",
      injectionScan: scan,
      serverPriceProtected: product.priceMinor,
    };
  }

  return {
    ok: true,
    status: 201,
    order: Object.freeze({
      sku,
      title: product.title,
      quantity,
      unitPriceMinor: product.priceMinor,
      subtotalMinor,
      discountMinor,
      finalTotalMinor,
      currency: product.currency,
      appliedCoupon,
      pricingSource: "SERVER_CATALOG_LOCKED",
    }),
    injectionScan: scan,
  };
}
