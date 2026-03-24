import express from "express";
import crypto from "crypto";

const app = express();

app.use(express.json({ limit: "20mb" }));
app.use(express.text({ type: ["text/*", "application/*"], limit: "20mb" }));

const KSEF_BASE_URL = process.env.KSEF_BASE_URL || "https://api-demo.ksef.mf.gov.pl";
const PORT = process.env.PORT || 3000;

/**
 * Ścieżki KSeF
 */
const SUCCESSFUL_INVOICES_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/successful`;

const FAILED_INVOICES_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/failed`;

const SESSION_STATUS_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}`;

const SEND_INVOICE_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/online/${sessionReferenceNumber}/invoices`;

const UPO_PATH = (sessionReferenceNumber, referenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/${referenceNumber}/upo`;

const CLOSE_SESSION_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/online/${sessionReferenceNumber}/close`;

function safeParseBody(req) {
  if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
    return req.body;
  }

  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch {
      throw new Error("Body nie jest poprawnym JSON-em");
    }
  }

  throw new Error("Nie udało się odczytać request body");
}

function requireString(obj, key) {
  if (!obj[key] || typeof obj[key] !== "string") {
    throw new Error(`Brak lub błędne pole: ${key}`);
  }
  return obj[key];
}

function optionalString(obj, key, defaultValue = "") {
  const value = obj[key];
  return typeof value === "string" ? value : defaultValue;
}

function optionalBoolean(obj, key, defaultValue = false) {
  return typeof obj[key] === "boolean" ? obj[key] : defaultValue;
}

function optionalNumber(obj, key, defaultValue = 0) {
  const value = Number(obj[key]);
  return Number.isFinite(value) ? value : defaultValue;
}

function requirePositiveNumber(obj, key) {
  const value = Number(obj[key]);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Brak lub błędne pole liczbowe: ${key}`);
  }
  return value;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function toPemCertificate(base64Cert) {
  const lines = base64Cert.match(/.{1,64}/g)?.join("\n") || base64Cert;
  return `-----BEGIN CERTIFICATE-----
${lines}
-----END CERTIFICATE-----`;
}

async function getKsefPublicKeyByUsage(requiredUsage) {
  const resp = await fetch(`${KSEF_BASE_URL}/v2/security/public-key-certificates`, {
    method: "GET",
    headers: {
      Accept: "application/json"
    }
  });

  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`KSeF cert fetch failed: ${resp.status} ${txt}`);
  }

  const data = await resp.json();

  if (!Array.isArray(data)) {
    throw new Error("Nieoczekiwany format odpowiedzi certyfikatów KSeF");
  }

  const certObj = data.find(
    c => Array.isArray(c.usage) && c.usage.includes(requiredUsage)
  );

  if (!certObj?.certificate) {
    throw new Error(`Nie znaleziono certyfikatu dla usage=${requiredUsage}`);
  }

  const certPem = toPemCertificate(certObj.certificate);
  const x509 = new crypto.X509Certificate(certPem);

  return x509.publicKey.export({
    type: "spki",
    format: "pem"
  }).toString();
}

function sha256Base64(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("base64");
}

function encryptXml(xmlText, aesKeyBase64, initializationVector) {
  const xmlBuffer = Buffer.from(xmlText, "utf8");
  const aesKey = Buffer.from(aesKeyBase64, "base64");
  const iv = Buffer.from(initializationVector, "base64");

  if (aesKey.length !== 32) {
    throw new Error(`AES key must be 32 bytes, got ${aesKey.length}`);
  }

  if (iv.length !== 16) {
    throw new Error(`IV must be 16 bytes, got ${iv.length}`);
  }

  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  const cipherText = Buffer.concat([
    cipher.update(xmlBuffer),
    cipher.final()
  ]);

  const encryptedBuffer = cipherText;

  return {
    xmlBuffer,
    encryptedBuffer,
    invoiceHash: sha256Base64(xmlBuffer),
    invoiceSize: xmlBuffer.length,
    encryptedInvoiceHash: sha256Base64(encryptedBuffer),
    encryptedInvoiceSize: encryptedBuffer.length,
    encryptedInvoiceContent: encryptedBuffer.toString("base64")
  };
}

async function readResponseBody(resp) {
  const contentType = (resp.headers.get("content-type") || "").toLowerCase();
  const text = await resp.text();

  let parsed = null;
  if (contentType.includes("application/json")) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
  }

  return {
    contentType,
    text,
    json: parsed
  };
}

async function callKsef(url, accessToken, options = {}) {
  const method = options.method || "GET";
  const accept = options.accept || "application/json";
  const contentType = options.contentType || (options.body ? "application/json" : undefined);

  const headers = {
    Authorization: `Bearer ${accessToken}`,
    Accept: accept,
    ...(contentType ? { "Content-Type": contentType } : {}),
    ...(options.headers || {})
  };

  const resp = await fetch(url, {
    method,
    headers,
    ...(options.body ? { body: options.body } : {})
  });

  const bodyRead = await readResponseBody(resp);

  return {
    status: resp.status,
    ok: resp.ok,
    headers: Object.fromEntries(resp.headers.entries()),
    contentType: bodyRead.contentType,
    body: bodyRead.json ?? { raw: bodyRead.text },
    raw: bodyRead.text
  };
}

function extractSessionSummary(sessionBody) {
  const source = sessionBody?.ksefResponse || sessionBody?.response || sessionBody || {};

  return {
    statusCode: source?.status?.code ?? source?.code ?? null,
    statusDescription: source?.status?.description ?? source?.description ?? "",
    invoiceCount: Number(source?.invoiceCount ?? 0),
    successfulInvoiceCount: Number(source?.successfulInvoiceCount ?? 0),
    failedInvoiceCount: Number(source?.failedInvoiceCount ?? 0),
    dateCreated: source?.dateCreated ?? "",
    dateUpdated: source?.dateUpdated ?? "",
    validUntil: source?.validUntil ?? ""
  };
}

function collectArraysDeep(node, found = []) {
  if (Array.isArray(node)) {
    found.push(node);
    for (const item of node) {
      collectArraysDeep(item, found);
    }
    return found;
  }

  if (node && typeof node === "object") {
    for (const value of Object.values(node)) {
      collectArraysDeep(value, found);
    }
  }

  return found;
}

function looksLikeInvoiceObject(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return false;
  }

  const possibleKeys = [
    "referenceNumber",
    "referenceNo",
    "invoiceReferenceNumber",
    "ksefNumber",
    "ksefReferenceNumber",
    "ksefReferenceNo",
    "invoiceKsefNumber",
    "invoiceNumber",
    "invoiceStatus",
    "acquisitionTimestamp",
    "dateAcquired",
    "dateAdded"
  ];

  return possibleKeys.some(key => Object.prototype.hasOwnProperty.call(obj, key));
}

function extractInvoiceList(anyBody) {
  const source =
    anyBody?.ksefResponse ||
    anyBody?.response ||
    anyBody?.data ||
    anyBody ||
    {};

  const directCandidates = [
    source?.invoices,
    source?.items,
    source?.data,
    source?.successfulInvoices,
    source?.invoiceList,
    source?.invoiceHeaderList,
    source?.successfulInvoiceList,
    source?.results,
    source?.content
  ];

  for (const candidate of directCandidates) {
    if (Array.isArray(candidate)) {
      const filtered = candidate.filter(looksLikeInvoiceObject);
      if (filtered.length > 0) {
        return filtered;
      }
      if (candidate.length > 0) {
        return candidate;
      }
    }
  }

  const deepArrays = collectArraysDeep(source, []);
  for (const arr of deepArrays) {
    const filtered = arr.filter(looksLikeInvoiceObject);
    if (filtered.length > 0) {
      return filtered;
    }
  }

  if (Array.isArray(source)) {
    return source;
  }

  return [];
}

function extractReferenceNumber(invoiceObj) {
  if (!invoiceObj || typeof invoiceObj !== "object") {
    return "";
  }

  return (
    invoiceObj.referenceNumber ||
    invoiceObj.referenceNo ||
    invoiceObj.invoiceReferenceNumber ||
    invoiceObj?.metadata?.referenceNumber ||
    invoiceObj?.invoiceMetadata?.referenceNumber ||
    invoiceObj?.invoice?.referenceNumber ||
    invoiceObj?.invoiceReference?.referenceNumber ||
    ""
  );
}

function extractKsefNumber(invoiceObj) {
  if (!invoiceObj || typeof invoiceObj !== "object") {
    return "";
  }

  return (
    invoiceObj.ksefNumber ||
    invoiceObj.ksefReferenceNumber ||
    invoiceObj.ksefReferenceNo ||
    invoiceObj.invoiceKsefNumber ||
    invoiceObj?.invoice?.ksefNumber ||
    invoiceObj?.invoiceKsef?.number ||
    ""
  );
}

function extractInvoiceStatus(invoiceObj) {
  if (!invoiceObj || typeof invoiceObj !== "object") {
    return "";
  }

  return (
    invoiceObj.invoiceStatus ||
    invoiceObj.status ||
    invoiceObj?.invoice?.status ||
    ""
  );
}

function extractAcquisitionTimestamp(invoiceObj) {
  if (!invoiceObj || typeof invoiceObj !== "object") {
    return "";
  }

  return (
    invoiceObj.acquisitionTimestamp ||
    invoiceObj.dateAcquired ||
    invoiceObj.dateAdded ||
    invoiceObj.receivedAt ||
    ""
  );
}

function pickBestInvoice(invoices) {
  if (!Array.isArray(invoices) || invoices.length === 0) {
    return null;
  }

  const scored = invoices.map(inv => {
    let score = 0;

    if (extractReferenceNumber(inv)) score += 2;
    if (extractKsefNumber(inv)) score += 5;
    if (extractInvoiceStatus(inv)) score += 1;
    if (extractAcquisitionTimestamp(inv)) score += 1;

    return { inv, score };
  });

  scored.sort((a, b) => b.score - a.score);

  return scored[0]?.inv || invoices[0];
}

function buildXmlFileName(referenceNumber) {
  const safe = String(referenceNumber || "UPO").replace(/[^a-zA-Z0-9._-]/g, "_");
  return `${safe}.xml`;
}

function buildPdfFileName(referenceNumber) {
  const safe = String(referenceNumber || "UPO").replace(/[^a-zA-Z0-9._-]/g, "_");
  return `${safe}.pdf`;
}

async function getSessionStatus(accessToken, sessionReferenceNumber) {
  const endpoint = SESSION_STATUS_PATH(sessionReferenceNumber);
  const result = await callKsef(endpoint, accessToken);

  return {
    endpoint,
    ...result
  };
}

async function getSessionFailed(accessToken, sessionReferenceNumber) {
  const endpoint = FAILED_INVOICES_PATH(sessionReferenceNumber);
  const result = await callKsef(endpoint, accessToken);

  return {
    endpoint,
    ...result
  };
}

async function getSessionSuccessful(accessToken, sessionReferenceNumber) {
  const endpoint = SUCCESSFUL_INVOICES_PATH(sessionReferenceNumber);
  const result = await callKsef(endpoint, accessToken);

  return {
    endpoint,
    ...result
  };
}

async function closeSession(accessToken, sessionReferenceNumber) {
  const endpoint = CLOSE_SESSION_PATH(sessionReferenceNumber);
  const result = await callKsef(endpoint, accessToken, {
    method: "POST",
    body: JSON.stringify({})
  });

  return {
    endpoint,
    ...result
  };
}

async function getInvoiceUpo(accessToken, sessionReferenceNumber, referenceNumber, prefer = "xml") {
  const endpoint = UPO_PATH(sessionReferenceNumber, referenceNumber);

  let accept = "application/xml";
  if (prefer === "pdf") {
    accept = "application/pdf";
  } else if (prefer === "json") {
    accept = "application/json";
  }

  const result = await callKsef(endpoint, accessToken, {
    method: "GET",
    accept
  });

  const isPdf = result.contentType.includes("application/pdf");
  const isXml =
    result.contentType.includes("application/xml") ||
    result.contentType.includes("text/xml") ||
    (!result.contentType.includes("application/json") && result.raw?.trim()?.startsWith("<"));

  return {
    endpoint,
    ...result,
    upoMimeType: isPdf
      ? "application/pdf"
      : isXml
        ? "application/xml"
        : result.contentType || "application/octet-stream",
    upoFileName: isPdf ? buildPdfFileName(`UPO_${referenceNumber}`) : buildXmlFileName(`UPO_${referenceNumber}`),
    upoText: isPdf ? "" : result.raw,
    upoBase64: Buffer.from(result.raw || "", isPdf ? "binary" : "utf8").toString("base64")
  };
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "ksef-helper works",
    baseUrl: KSEF_BASE_URL
  });
});

app.post("/encrypt-token", async (req, res) => {
  try {
    const body = safeParseBody(req);
    const plainText = requireString(body, "plainText");

    const publicKeyPem = await getKsefPublicKeyByUsage("KsefTokenEncryption");

    const encryptedBuffer = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      Buffer.from(plainText, "utf8")
    );

    return res.json({
      encryptedToken: encryptedBuffer.toString("base64")
    });
  } catch (e) {
    console.error("POST /encrypt-token error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/session-encryption", async (req, res) => {
  try {
    const publicKeyPem = await getKsefPublicKeyByUsage("SymmetricKeyEncryption");

    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    const encryptedSymmetricKey = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      aesKey
    );

    return res.json({
      encryptedSymmetricKey: encryptedSymmetricKey.toString("base64"),
      initializationVector: iv.toString("base64"),
      aesKeyBase64: aesKey.toString("base64")
    });
  } catch (e) {
    console.error("POST /session-encryption error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/encrypt-document", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const xmlText = requireString(body, "xmlText");
    const aesKeyBase64 = requireString(body, "aesKeyBase64");
    const initializationVector = requireString(body, "initializationVector");

    const encrypted = encryptXml(xmlText, aesKeyBase64, initializationVector);

    return res.json({
      invoiceHash: encrypted.invoiceHash,
      invoiceSize: encrypted.invoiceSize,
      encryptedInvoiceHash: encrypted.encryptedInvoiceHash,
      encryptedInvoiceSize: encrypted.encryptedInvoiceSize,
      encryptedInvoiceContent: encrypted.encryptedInvoiceContent
    });
  } catch (e) {
    console.error("POST /encrypt-document error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/send-invoice", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");
    const xmlText = requireString(body, "xmlText");
    const aesKeyBase64 = requireString(body, "aesKeyBase64");
    const initializationVector = requireString(body, "initializationVector");

    const encrypted = encryptXml(xmlText, aesKeyBase64, initializationVector);

    const payload = {
      invoiceHash: encrypted.invoiceHash,
      invoiceSize: encrypted.invoiceSize,
      encryptedInvoiceHash: encrypted.encryptedInvoiceHash,
      encryptedInvoiceSize: encrypted.encryptedInvoiceSize,
      encryptedInvoiceContent: encrypted.encryptedInvoiceContent
    };

    const rawBody = JSON.stringify(payload);
    const endpoint = SEND_INVOICE_PATH(sessionReferenceNumber);

    console.log("=== KSEF SEND DEBUG ===");
    console.log("endpoint:", endpoint);
    console.log("xmlCharLength:", xmlText.length);
    console.log("xmlByteLength:", encrypted.xmlBuffer.length);
    console.log("invoiceHash:", payload.invoiceHash);
    console.log("invoiceSize:", payload.invoiceSize);
    console.log("encryptedInvoiceHash:", payload.encryptedInvoiceHash);
    console.log("encryptedInvoiceSize:", payload.encryptedInvoiceSize);
    console.log("rawRequestBodyLength:", Buffer.byteLength(rawBody, "utf8"));
    console.log("rawRequestBody:", rawBody);

    const result = await callKsef(endpoint, accessToken, {
      method: "POST",
      body: rawBody
    });

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint,
      xmlCharLength: xmlText.length,
      xmlByteLength: encrypted.xmlBuffer.length,
      requestPayload: payload,
      rawRequestBody: rawBody,
      rawRequestBodyLength: Buffer.byteLength(rawBody, "utf8"),
      ksefStatus: result.status,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /send-invoice error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/send-invoice-raw", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");

    const payload = {
      invoiceHash: requireString(body, "invoiceHash"),
      invoiceSize: requirePositiveNumber(body, "invoiceSize"),
      encryptedInvoiceHash: requireString(body, "encryptedInvoiceHash"),
      encryptedInvoiceSize: requirePositiveNumber(body, "encryptedInvoiceSize"),
      encryptedInvoiceContent: requireString(body, "encryptedInvoiceContent")
    };

    const rawBody = JSON.stringify(payload);
    const endpoint = SEND_INVOICE_PATH(sessionReferenceNumber);

    const result = await callKsef(endpoint, accessToken, {
      method: "POST",
      body: rawBody
    });

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint,
      requestPayload: payload,
      rawRequestBody: rawBody,
      rawRequestBodyLength: Buffer.byteLength(rawBody, "utf8"),
      ksefStatus: result.status,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /send-invoice-raw error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/session-status", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");

    const result = await getSessionStatus(accessToken, sessionReferenceNumber);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint: result.endpoint,
      ksefStatus: result.status,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /session-status error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/session-failed", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");

    const result = await getSessionFailed(accessToken, sessionReferenceNumber);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint: result.endpoint,
      ksefStatus: result.status,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /session-failed error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/session-successful", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");

    const result = await getSessionSuccessful(accessToken, sessionReferenceNumber);
    const invoices = extractInvoiceList(result.body);
    const selectedInvoice = pickBestInvoice(invoices);
    const referenceNumber = extractReferenceNumber(selectedInvoice);
    const ksefNumber = extractKsefNumber(selectedInvoice);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint: result.endpoint,
      ksefStatus: result.status,
      invoiceCountParsed: invoices.length,
      selectedReferenceNumber: referenceNumber,
      selectedKsefNumber: ksefNumber,
      selectedInvoice,
      successfulInvoicesParsed: invoices,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /session-successful error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/invoice-upo", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");
    const referenceNumber = requireString(body, "referenceNumber");
    const prefer = optionalString(body, "prefer", "xml");

    const result = await getInvoiceUpo(accessToken, sessionReferenceNumber, referenceNumber, prefer);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint: result.endpoint,
      ksefStatus: result.status,
      contentType: result.contentType,
      upoMimeType: result.upoMimeType,
      upoFileName: result.upoFileName,
      upoText: result.upoText,
      upoBase64: result.upoBase64,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /invoice-upo error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/session-close", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");

    const result = await closeSession(accessToken, sessionReferenceNumber);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint: result.endpoint,
      ksefStatus: result.status,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /session-close error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/session-debug", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");

    const statusEndpoint = SESSION_STATUS_PATH(sessionReferenceNumber);
    const failedEndpoint = FAILED_INVOICES_PATH(sessionReferenceNumber);
    const successfulEndpoint = SUCCESSFUL_INVOICES_PATH(sessionReferenceNumber);

    const [statusResult, failedResult, successfulResult] = await Promise.all([
      callKsef(statusEndpoint, accessToken),
      callKsef(failedEndpoint, accessToken),
      callKsef(successfulEndpoint, accessToken)
    ]);

    const successfulInvoices = extractInvoiceList(successfulResult.body);
    const selectedInvoice = pickBestInvoice(successfulInvoices);

    return res.json({
      baseUrl: KSEF_BASE_URL,
      sessionReferenceNumber,
      status: {
        endpoint: statusEndpoint,
        httpStatus: statusResult.status,
        response: statusResult.body
      },
      failed: {
        endpoint: failedEndpoint,
        httpStatus: failedResult.status,
        response: failedResult.body
      },
      successful: {
        endpoint: successfulEndpoint,
        httpStatus: successfulResult.status,
        parsedInvoiceCount: successfulInvoices.length,
        selectedReferenceNumber: extractReferenceNumber(selectedInvoice),
        selectedKsefNumber: extractKsefNumber(selectedInvoice),
        selectedInvoice,
        successfulInvoicesParsed: successfulInvoices,
        response: successfulResult.body
      }
    });
  } catch (e) {
    console.error("POST /session-debug error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/finalize-session", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");
    const closeAfter = optionalBoolean(body, "closeAfter", true);
    const pollCount = optionalNumber(body, "pollCount", 10);
    const pollDelayMs = optionalNumber(body, "pollDelayMs", 1500);
    const preferUpo = optionalString(body, "preferUpo", "xml");

    let statusResult = null;
    let summary = null;
    let i = 0;

    for (i = 0; i < pollCount; i++) {
      statusResult = await getSessionStatus(accessToken, sessionReferenceNumber);
      summary = extractSessionSummary(statusResult.body);

      if (summary.failedInvoiceCount > 0 || summary.successfulInvoiceCount > 0) {
        break;
      }

      if (i < pollCount - 1) {
        await sleep(pollDelayMs);
      }
    }

    if (!statusResult) {
      throw new Error("Nie udało się pobrać statusu sesji");
    }

    if (summary.failedInvoiceCount > 0) {
      const failedResult = await getSessionFailed(accessToken, sessionReferenceNumber);

      let closeResult = null;
      if (closeAfter) {
        closeResult = await closeSession(accessToken, sessionReferenceNumber);
      }

      return res.status(200).json({
        ok: false,
        processed: true,
        accepted: false,
        sessionReferenceNumber,
        sessionStatusCode: summary.statusCode,
        sessionStatusDescription: summary.statusDescription,
        invoiceCount: summary.invoiceCount,
        successfulInvoiceCount: summary.successfulInvoiceCount,
        failedInvoiceCount: summary.failedInvoiceCount,
        failedEndpoint: failedResult.endpoint,
        failedResponse: failedResult.body,
        closeAttempted: closeAfter,
        closeResponse: closeResult
          ? {
              endpoint: closeResult.endpoint,
              httpStatus: closeResult.status,
              response: closeResult.body
            }
          : null,
        message: "Sesja zawiera błędne faktury"
      });
    }

    if (summary.successfulInvoiceCount < 1) {
      return res.status(200).json({
        ok: true,
        processed: false,
        accepted: false,
        sessionReferenceNumber,
        sessionStatusCode: summary.statusCode,
        sessionStatusDescription: summary.statusDescription,
        invoiceCount: summary.invoiceCount,
        successfulInvoiceCount: summary.successfulInvoiceCount,
        failedInvoiceCount: summary.failedInvoiceCount,
        pollsPerformed: i + 1,
        message: "Faktura jeszcze nie jest przetworzona końcowo"
      });
    }

    let successfulResult = null;
    let invoices = [];
    let selectedInvoice = null;
    let successPollsPerformed = 0;

    for (let s = 0; s < pollCount; s++) {
      successfulResult = await getSessionSuccessful(accessToken, sessionReferenceNumber);
      invoices = extractInvoiceList(successfulResult.body);
      selectedInvoice = pickBestInvoice(invoices);
      successPollsPerformed = s + 1;

      if (selectedInvoice && (extractReferenceNumber(selectedInvoice) || extractKsefNumber(selectedInvoice))) {
        break;
      }

      if (s < pollCount - 1) {
        await sleep(pollDelayMs);
      }
    }

    console.log("SUCCESSFUL RAW:", JSON.stringify(successfulResult?.body, null, 2));
    console.log("SUCCESSFUL PARSED COUNT:", invoices.length);
    console.log("SUCCESSFUL SELECTED INVOICE:", selectedInvoice);

    if (!selectedInvoice) {
      let closeResult = null;
      if (closeAfter) {
        closeResult = await closeSession(accessToken, sessionReferenceNumber);
      }

      return res.status(200).json({
        ok: false,
        processed: true,
        accepted: false,
        sessionReferenceNumber,
        sessionStatusCode: summary.statusCode,
        sessionStatusDescription: summary.statusDescription,
        successfulEndpoint: successfulResult?.endpoint || "",
        successfulResponse: successfulResult?.body || null,
        successfulInvoicesParsed: invoices,
        successPollsPerformed,
        closeAttempted: closeAfter,
        closeResponse: closeResult
          ? {
              endpoint: closeResult.endpoint,
              httpStatus: closeResult.status,
              response: closeResult.body
            }
          : null,
        message: "Nie udało się odczytać danych poprawnej faktury z endpointu successful"
      });
    }

    const referenceNumber = extractReferenceNumber(selectedInvoice);
    const ksefNumber = extractKsefNumber(selectedInvoice);
    const invoiceStatus = extractInvoiceStatus(selectedInvoice);
    const acquisitionTimestamp = extractAcquisitionTimestamp(selectedInvoice);

    console.log("REFERENCE NUMBER:", referenceNumber);
    console.log("KSEF NUMBER:", ksefNumber);

    let upoResult = null;
    let upoReady = false;

    if (referenceNumber) {
      try {
        upoResult = await getInvoiceUpo(
          accessToken,
          sessionReferenceNumber,
          referenceNumber,
          preferUpo
        );

        if (upoResult && upoResult.status >= 200 && upoResult.status < 300) {
          upoReady = true;
        }
      } catch (upoErr) {
        console.error("UPO fetch error:", upoErr);
      }
    }

    let closeResult = null;
    if (closeAfter) {
      closeResult = await closeSession(accessToken, sessionReferenceNumber);
    }

    return res.status(200).json({
      ok: true,
      processed: true,
      accepted: true,
      sessionReferenceNumber,
      sessionStatusCode: summary.statusCode,
      sessionStatusDescription: summary.statusDescription,
      invoiceCount: summary.invoiceCount,
      successfulInvoiceCount: summary.successfulInvoiceCount,
      failedInvoiceCount: summary.failedInvoiceCount,
      referenceNumber,
      ksefNumber,
      invoiceStatus,
      acquisitionTimestamp,
      selectedReferenceNumber: referenceNumber,
      selectedKsefNumber: ksefNumber,
      selectedInvoice,
      successfulInvoicesParsed: invoices,
      successPollsPerformed,
      upoReady,
      upo: upoResult
        ? {
            endpoint: upoResult.endpoint,
            httpStatus: upoResult.status,
            contentType: upoResult.contentType,
            upoMimeType: upoResult.upoMimeType,
            upoFileName: upoResult.upoFileName,
            upoText: upoResult.upoText,
            upoBase64: upoResult.upoBase64,
            response: upoResult.body
          }
        : null,
      closeAttempted: closeAfter,
      closeResponse: closeResult
        ? {
            endpoint: closeResult.endpoint,
            httpStatus: closeResult.status,
            response: closeResult.body
          }
        : null,
      message: "Faktura przyjęta; pobrano dane końcowe sesji"
    });
  } catch (e) {
    console.error("POST /finalize-session error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`KSEF_BASE_URL=${KSEF_BASE_URL}`);
});
