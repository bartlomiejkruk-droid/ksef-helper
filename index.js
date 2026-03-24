import express from "express";
import crypto from "crypto";

const app = express();

app.use(express.json({ limit: "20mb" }));
app.use(express.text({ type: ["text/*", "application/*"], limit: "20mb" }));

const KSEF_BASE_URL = process.env.KSEF_BASE_URL || "https://api-demo.ksef.mf.gov.pl";
const PORT = process.env.PORT || 3000;

// ================= PATHS =================

const SUCCESSFUL_INVOICES_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/successful`;

const UPO_PATH = (sessionReferenceNumber, referenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/${referenceNumber}/upo`;

const CLOSE_SESSION_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/online/${sessionReferenceNumber}/close`;

// ================= UTILS =================

function safeParseBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") return JSON.parse(req.body);
  throw new Error("Invalid body");
}

function requireString(obj, key) {
  if (!obj[key]) throw new Error(`Missing ${key}`);
  return obj[key];
}

function optionalBoolean(obj, key, def = false) {
  return typeof obj[key] === "boolean" ? obj[key] : def;
}

function optionalNumber(obj, key, def = 0) {
  const v = Number(obj[key]);
  return Number.isFinite(v) ? v : def;
}

function optionalString(obj, key, def = "") {
  return typeof obj[key] === "string" ? obj[key] : def;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function callKsef(url, accessToken, options = {}) {
  const resp = await fetch(url, {
    method: options.method || "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: options.accept || "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {})
    },
    ...(options.body ? { body: options.body } : {})
  });

  const text = await resp.text();

  let json = null;
  try { json = JSON.parse(text); } catch {}

  return {
    status: resp.status,
    ok: resp.ok,
    body: json || text,
    raw: text,
    contentType: resp.headers.get("content-type") || ""
  };
}

// ================= PARSING =================

function extractSessionSummary(body) {
  const s = body?.ksefResponse || body?.response || body || {};
  return {
    statusCode: s?.status?.code ?? null,
    statusDescription: s?.status?.description ?? "",
    invoiceCount: Number(s?.invoiceCount ?? 0),
    successfulInvoiceCount: Number(s?.successfulInvoiceCount ?? 0),
    failedInvoiceCount: Number(s?.failedInvoiceCount ?? 0)
  };
}

function extractInvoices(body) {
  const src = body?.ksefResponse || body?.response || body || {};

  if (Array.isArray(src)) return src;
  if (Array.isArray(src.invoices)) return src.invoices;
  if (Array.isArray(src.items)) return src.items;
  if (Array.isArray(src.data)) return src.data;

  return [];
}

function extractReferenceNumber(inv) {
  if (!inv) return "";

  return (
    inv.referenceNumber ||
    inv.referenceNo ||
    inv.invoiceReferenceNumber ||
    inv?.metadata?.referenceNumber ||
    inv?.invoiceMetadata?.referenceNumber ||
    ""
  );
}

function extractKsefNumber(inv) {
  if (!inv) return "";

  return (
    inv.ksefNumber ||
    inv.ksefReferenceNumber ||
    inv.invoiceKsefNumber ||
    ""
  );
}

// ================= FINALIZE =================

app.post("/finalize-session", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");

    const closeAfter = optionalBoolean(body, "closeAfter", true);
    const pollCount = optionalNumber(body, "pollCount", 5);
    const pollDelayMs = optionalNumber(body, "pollDelayMs", 1000);
    const preferUpo = optionalString(body, "preferUpo", "xml");

    let summary = null;

    // ===== POLL =====
    for (let i = 0; i < pollCount; i++) {
      const status = await callKsef(
        `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}`,
        accessToken
      );

      summary = extractSessionSummary(status.body);

      if (summary.successfulInvoiceCount > 0 || summary.failedInvoiceCount > 0) {
        break;
      }

      await sleep(pollDelayMs);
    }

    // ===== FAILED =====
    if (summary.failedInvoiceCount > 0) {
      return res.json({
        ok: false,
        processed: true,
        accepted: false,
        message: "Sesja zawiera błędy",
        summary
      });
    }

    // ===== NIEPRZETWORZONE =====
    if (summary.successfulInvoiceCount < 1) {
      return res.json({
        ok: true,
        processed: false,
        accepted: false,
        message: "Jeszcze się przetwarza",
        summary
      });
    }

    // ===== SUCCESSFUL =====
    const successful = await callKsef(
      SUCCESSFUL_INVOICES_PATH(sessionReferenceNumber),
      accessToken
    );

    console.log("SUCCESSFUL RAW:", successful.raw);

    const invoices = extractInvoices(successful.body);

    if (!invoices.length) {
      return res.json({
        ok: false,
        processed: true,
        accepted: false,
        message: "Brak faktur w successful",
        debug: successful.body
      });
    }

    const invoice = invoices[0];

    const referenceNumber = extractReferenceNumber(invoice);
    const ksefNumber = extractKsefNumber(invoice);

    console.log("INVOICE:", invoice);
    console.log("REFERENCE:", referenceNumber);

    // ===== UPO =====
    let upo = null;

    if (referenceNumber) {
      const upoResp = await callKsef(
        UPO_PATH(sessionReferenceNumber, referenceNumber),
        accessToken,
        { accept: preferUpo === "pdf" ? "application/pdf" : "application/xml" }
      );

      upo = {
        contentType: upoResp.contentType,
        base64: Buffer.from(upoResp.raw).toString("base64")
      };
    }

    // ===== CLOSE =====
    let closeResp = null;

    if (closeAfter) {
      closeResp = await callKsef(
        CLOSE_SESSION_PATH(sessionReferenceNumber),
        accessToken,
        { method: "POST", body: "{}" }
      );
    }

    return res.json({
      ok: true,
      processed: true,
      accepted: true,
      sessionReferenceNumber,
      referenceNumber,
      ksefNumber,
      invoice,
      upo,
      close: closeResp?.body || null,
      summary
    });

  } catch (e) {
    console.error("FINALIZE ERROR:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log("KSeF helper running:", PORT);
});
