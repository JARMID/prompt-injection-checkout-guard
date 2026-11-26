/**
 * Zero-Trust Server-Side Checkout Guardrail for LLM Shopping Agents
 * -----------------------------------------------------------------
 * Core principle: Treat EVERY user message AND EVERY LLM tool-call output
 * as untrusted input. Never let an LLM supply unit prices, override discount
 * caps, pollute object prototypes, or invoke privileged backend tools.
 */

const MAX_USER_MESSAGE_CHARS = 8192;
const ZERO_WIDTH_AND_BIDI_RX = /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/;
const ZERO_WIDTH_STRIP_RX = /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g;

export const INJECTION_PATTERNS = [
  {
    id: "ignore_instructions",
    rx: /\b(ignore|disregard|forget|override|bypass)\b.{0,45}\b(previous|prior|system|all|above|safety|original)\b.{0,35}\b(instruction|prompt|rule|policy|guideline)/i,
  },
  {
    id: "role_escalation",
    rx: /\b(you are now|act as|switch to|enter|pretend to be|assume)\b.{0,35}\b(admin|administrator|developer|root|system|debug|qa|maintenance|pricing|superuser|manager)\b/i,
  },
  {
    id: "direct_price_override",
    rx: /\b(set|change|update|force|override|make|adjust)\b.{0,30}\b(price|total|amount|cost|subtotal|invoice)\b.{0,20}\b(to|=|:|at)?\s*(0|1|\$?0\.01|1\s*da|0\s*da|free|zero)\b/i,
  },
  {
    id: "unbounded_discount",
    rx: /\b(9[0-9]%|100%|99\.9%|unlimited|admin|vip|internal|staff|free)\b.{0,25}\b(discount|coupon|promo|voucher|off|rebate)\b/i,
  },
  {
    id: "tool_smuggling",
    rx: /\b(apply_discount|update_price|set_price|bypass_payment|create_admin_order|exec_sql|grant_admin|override_total)\s*\(/i,
  },
  {
    id: "delimiter_escape",
    rx: /(<\s*\/?\s*system\s*>|\[\/?SYSTEM\]|###\s*SYSTEM\s*(OVERRIDE|PROMPT)|BEGIN\s+SYSTEM\s+PROMPT|<\|im_start\|>\s*system)/i,
  },
  {
    id: "secret_exfiltration",
    rx: /\b(reveal|print|dump|output|show|leak|exfiltrate|echo)\b.{0,35}\b(system prompt|api[ _-]?key|secret|env|environment|database|password|token|credentials?)\b/i,
  },
  {
    id: "json_field_smuggling",
    rx: /"(unit_?price|override_?price|discount_?percent|final_?total|is_?admin)"\s*:/i,
  },
];

const CHECKOUT_TOOL_NAME = "create_checkout_intent";
const CHECKOUT_ALLOWED_KEYS = new Set(["sku", "quantity", "couponCode"]);
const KNOWN_TAMPER_KEYS = new Set([
  "unitPrice",
  "unit_price",
  "price",
  "total",
  "finalTotal",
  "overridePrice",
  "discountPercent",
  "discount",
  "isAdmin",
  "role",
]);

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Check raw bytes for hidden bidi/zero-width characters and length bombs,
 * then apply NFKC normalization + whitespace collapsing before scanning rules.
 */
export function scanPromptInjection(userText) {
  const raw = typeof userText === "string" ? userText : String(userText ?? "");
  const matched = [];

  if (raw.length > MAX_USER_MESSAGE_CHARS) {
    matched.push("oversized_input");
  }
  if (ZERO_WIDTH_AND_BIDI_RX.test(raw)) {
    matched.push("hidden_unicode_bidi");
  }

  const normalized = raw
    .slice(0, MAX_USER_MESSAGE_CHARS)
    .normalize("NFKC")
    .replace(ZERO_WIDTH_STRIP_RX, "")
    .replace(/\s+/g, " ")
    .trim();

  for (const rule of INJECTION_PATTERNS) {
    if (rule.rx.test(normalized)) {
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
 * Validate an LLM-proposed checkout tool call against strict least-privilege
 * allowlists, injection scanning, and server-authoritative catalog pricing.
 *
 * Defense-in-depth ordering:
 * 1. Tool allowlist (strictly `create_checkout_intent` for checkout mutations)
 * 2. Strict argument allowlist (`sku`, `quantity`, `couponCode` only)
 * 3. Prompt injection gate BEFORE catalog/coupon lookups (prevents pricing/SKU oracles)
 * 4. Prototype-safe catalog lookup and hard server coupon ceiling (30% max)
 */
export function executeGuardedCheckout({
  userMessage,
  llmToolCall,
  catalog,
  coupons = {},
}) {
  const scan = scanPromptInjection(userMessage);

  // Layer 1: Strictly allow only the bounded checkout intent tool
  const toolName = typeof llmToolCall?.tool === "string" ? llmToolCall.tool : "";
  if (toolName !== CHECKOUT_TOOL_NAME) {
    return {
      ok: false,
      status: 403,
      reason: "forbidden_tool_invocation",
      toolName,
      injectionScan: scan,
    };
  }

  // Layer 2: Strict argument key allowlist (rejects ALL unexpected keys, not just a blocklist)
  const args = llmToolCall?.arguments;
  if (!isPlainObject(args)) {
    return {
      ok: false,
      status: 400,
      reason: "invalid_tool_arguments",
      injectionScan: scan,
    };
  }

  const ownKeys = Object.keys(args);
  const unexpectedKeys = ownKeys.filter((k) => !CHECKOUT_ALLOWED_KEYS.has(k));
  if (unexpectedKeys.length > 0) {
    const hasKnownTamper = unexpectedKeys.some((k) => KNOWN_TAMPER_KEYS.has(k));
    return {
      ok: false,
      status: 400,
      reason: hasKnownTamper ? "client_price_tampering_rejected" : "unexpected_tool_arguments",
      smuggledFields: unexpectedKeys,
      injectionScan: scan,
    };
  }

  // Layer 3: Block detected prompt injection BEFORE catalog/coupon queries (zero oracle leakage)
  if (scan.flagged) {
    return {
      ok: false,
      status: 403,
      reason: "prompt_injection_blocked",
      injectionScan: scan,
    };
  }

  // Layer 4: Strict schema validation (SKU + positive bounded integer quantity only)
  const sku = typeof args.sku === "string" ? args.sku.trim().toUpperCase() : "";
  const quantity = args.quantity;
  if (!sku || !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 50) {
    return {
      ok: false,
      status: 400,
      reason: "invalid_sku_or_quantity",
      injectionScan: scan,
    };
  }

  if (!isPlainObject(catalog) || !Object.hasOwn(catalog, sku)) {
    return { ok: false, status: 404, reason: "sku_not_found", injectionScan: scan };
  }
  const product = catalog[sku];
  if (
    !product ||
    !Number.isSafeInteger(product.priceMinor) ||
    product.priceMinor <= 0 ||
    typeof product.currency !== "string"
  ) {
    return { ok: false, status: 500, reason: "invalid_server_catalog_record", injectionScan: scan };
  }

  // Layer 5: Server-authoritative pricing & prototype-safe bounded coupon verification
  let discountMinor = 0;
  let appliedCoupon = null;
  if (args.couponCode !== undefined && args.couponCode !== null && args.couponCode !== "") {
    if (typeof args.couponCode !== "string") {
      return { ok: false, status: 400, reason: "invalid_coupon_type", injectionScan: scan };
    }
    const code = args.couponCode.trim().toUpperCase();
    if (!isPlainObject(coupons) || !Object.hasOwn(coupons, code)) {
      return { ok: false, status: 422, reason: "invalid_or_inactive_coupon", injectionScan: scan };
    }
    const coupon = coupons[code];
    if (
      !coupon ||
      coupon.active !== true ||
      typeof coupon.percentOff !== "number" ||
      !Number.isFinite(coupon.percentOff) ||
      coupon.percentOff < 0 ||
      coupon.percentOff > 100
    ) {
      return { ok: false, status: 422, reason: "invalid_or_inactive_coupon", injectionScan: scan };
    }
    const maxAllowedPct = Math.min(coupon.percentOff, 30); // Hard policy ceiling: 30% max
    discountMinor = Math.floor((product.priceMinor * quantity * maxAllowedPct) / 100);
    appliedCoupon = code;
  }

  const subtotalMinor = product.priceMinor * quantity;
  if (!Number.isSafeInteger(subtotalMinor)) {
    return { ok: false, status: 422, reason: "order_total_overflow", injectionScan: scan };
  }
  const finalTotalMinor = subtotalMinor - discountMinor;

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
