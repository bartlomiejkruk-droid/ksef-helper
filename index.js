import express from "express";
import crypto from "crypto";

const app = express();

app.use(express.json({ limit: "20mb" }));
app.use(express.text({ type: ["text/*", "application/*"], limit: "20mb" }));

const KSEF_BASE_URL = process.env.KSEF_BASE_URL || "https://api-demo.ksef.mf.gov.pl";
const PORT = process.env.PORT || 3000;

/**
 * KSeF endpoints
 * Status faktury w sesji:
 * GET /sessions/{referenceNumber}/invoices/{invoiceReferenceNumber}
 * UPO:
 * GET /sessions/{referenceNumber}/invoices/{invoiceReferenceNumber}/upo
 * GET /sessions/{referenceNumber}/invoices/ksef/{ksefNumber}/upo
 */
const FAILED_INVOICES_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/failed`;

const SESSION_STATUS_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}`;

const SEND_INVOICE_PATH = (sessionReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/online/${sessionReferenceNumber}/invoices`;

const INVOICE_STATUS_PATH = (sessionReferenceNumber, invoiceReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/${encodeURIComponent(invoiceReferenceNumber)}`;

const UPO_BY_REFERENCE_PATH = (sessionReferenceNumber, invoiceReferenceNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/${encodeURIComponent(invoiceReferenceNumber)}/upo`;

const UPO_BY_KSEF_PATH = (sessionReferenceNumber, ksefNumber) =>
  `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/ksef/${encodeURIComponent(ksefNumber)}/upo`;

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

  return {
    xmlBuffer,
    encryptedBuffer: cipherText,
    invoiceHash: sha256Base64(xmlBuffer),
    invoiceSize: xmlBuffer.length,
    encryptedInvoiceHash: sha256Base64(cipherText),
    encryptedInvoiceSize: cipherText.length,
    encryptedInvoiceContent: cipherText.toString("base64")
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

function extractInvoiceReferenceNumberFromSendResponse(anyBody) {
  const source = anyBody?.ksefResponse || anyBody?.response || anyBody?.data || anyBody || {};

  return (
    source?.invoiceReferenceNumber ||
    source?.referenceNumber ||
    source?.elementReferenceNumber ||
    source?.invoice?.invoiceReferenceNumber ||
    source?.invoice?.referenceNumber ||
    ""
  );
}

function extractReferenceNumber(invoiceObj) {
  if (!invoiceObj || typeof invoiceObj !== "object") {
    return "";
  }

  return (
    invoiceObj.invoiceReferenceNumber ||
    invoiceObj.referenceNumber ||
    invoiceObj.referenceNo ||
    invoiceObj.invoice?.invoiceReferenceNumber ||
    invoiceObj.invoice?.referenceNumber ||
    invoiceObj.metadata?.referenceNumber ||
    ""
  );
}

function extractKsefNumber(invoiceObj) {
  if (!invoiceObj || typeof invoiceObj !== "object") {
    return "";
  }

  return (
    invoiceObj.ksefNumber ||
    invoiceObj.invoiceKsefNumber ||
    invoiceObj.invoice?.ksefNumber ||
    invoiceObj.ksef?.number ||
    ""
  );
}

function extractInvoiceStatus(invoiceObj) {
  if (!invoiceObj || typeof invoiceObj !== "object") {
    return "";
  }

  const statusObj = invoiceObj.status;

  if (typeof statusObj === "string") {
    return statusObj;
  }

  return (
    statusObj?.code ||
    statusObj?.description ||
    invoiceObj.invoiceStatus ||
    invoiceObj.processingStatus ||
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

function extractFailedInvoices(anyBody) {
  const source = anyBody?.ksefResponse || anyBody?.response || anyBody || {};

  if (Array.isArray(source?.invoices)) return source.invoices;
  if (Array.isArray(source?.items)) return source.items;
  if (Array.isArray(source?.data)) return source.data;
  if (Array.isArray(source)) return source;

  return [];
}

function extractFailedStatusObject(failedInvoiceObj) {
  if (!failedInvoiceObj || typeof failedInvoiceObj !== "object") {
    return {};
  }

  return failedInvoiceObj.status || failedInvoiceObj?.invoice?.status || {};
}

function extractDuplicateInfoFromFailedResponse(failedBody) {
  const failedInvoices = extractFailedInvoices(failedBody);

  for (const failedInvoice of failedInvoices) {
    const statusObj = extractFailedStatusObject(failedInvoice);
    const statusCode = String(statusObj?.code || "");
    const statusDescription = statusObj?.description || "";
    const details = statusObj?.details || {};

    if (statusCode === "440") {
      return {
        isDuplicate: true,
        duplicateStatusCode: statusCode,
        duplicateStatusDescription: statusDescription,
        originalKsefNumber: details?.originalKsefNumber || "",
        originalSessionReferenceNumber: details?.originalSessionReferenceNumber || "",
        originalInvoiceNumber: details?.originalInvoiceNumber || "",
        originalReferenceNumber: details?.originalReferenceNumber || "",
        duplicateRawDetails: details,
        duplicateFailedInvoice: failedInvoice
      };
    }
  }

  return {
    isDuplicate: false,
    duplicateStatusCode: "",
    duplicateStatusDescription: "",
    originalKsefNumber: "",
    originalSessionReferenceNumber: "",
    originalInvoiceNumber: "",
    originalReferenceNumber: "",
    duplicateRawDetails: null,
    duplicateFailedInvoice: null
  };
}

function extractSuccessfulEndpointError(anyBody) {
  const source = anyBody?.ksefResponse || anyBody?.response || anyBody || {};
  const exception = source?.exception || {};

  const details = Array.isArray(exception?.exceptionDetailList)
    ? exception.exceptionDetailList
    : Array.isArray(source?.exceptionDetailList)
      ? source.exceptionDetailList
      : [];

  let flattenedMessages = [];
  for (const item of details) {
    if (Array.isArray(item?.details)) {
      flattenedMessages = flattenedMessages.concat(item.details.map(x => String(x)));
    }
    if (item?.exceptionDescription) {
      flattenedMessages.push(String(item.exceptionDescription));
    }
    if (item?.message) {
      flattenedMessages.push(String(item.message));
    }
  }

  const joined = flattenedMessages.join(" | ").toLowerCase();

  return {
    hasError: Boolean(details.length > 0 || exception?.exceptionDescription),
    exceptionCode: String(details?.[0]?.exceptionCode || exception?.exceptionCode || ""),
    exceptionDescription: String(details?.[0]?.exceptionDescription || exception?.exceptionDescription || ""),
    exceptionDetailList: details,
    flattenedMessages,
    isReferenceFormatError:
      joined.includes("invoicereferencenumber") &&
      joined.includes("not in the correct format")
  };
}

async function getSessionStatus(accessToken, sessionReferenceNumber) {
  const endpoint = SESSION_STATUS_PATH(sessionReferenceNumber);
  const result = await callKsef(endpoint, accessToken);
  return { endpoint, ...result };
}

async function getSessionFailed(accessToken, sessionReferenceNumber) {
  const endpoint = FAILED_INVOICES_PATH(sessionReferenceNumber);
  const result = await callKsef(endpoint, accessToken);
  return { endpoint, ...result };
}

async function getInvoiceStatus(accessToken, sessionReferenceNumber, invoiceReferenceNumber) {
  const endpoint = INVOICE_STATUS_PATH(sessionReferenceNumber, invoiceReferenceNumber);
  const result = await callKsef(endpoint, accessToken);
  return { endpoint, ...result };
}

async function closeSession(accessToken, sessionReferenceNumber) {
  const endpoint = CLOSE_SESSION_PATH(sessionReferenceNumber);
  const result = await callKsef(endpoint, accessToken, {
    method: "POST",
    body: JSON.stringify({})
  });
  return { endpoint, ...result };
}

async function getInvoiceUpo(accessToken, sessionReferenceNumber, options = {}) {
  const invoiceReferenceNumber = options.invoiceReferenceNumber || "";
  const ksefNumber = options.ksefNumber || "";
  const prefer = options.prefer || "xml";

  let endpoint = "";
  if (invoiceReferenceNumber) {
    endpoint = UPO_BY_REFERENCE_PATH(sessionReferenceNumber, invoiceReferenceNumber);
  } else if (ksefNumber) {
    endpoint = UPO_BY_KSEF_PATH(sessionReferenceNumber, ksefNumber);
  } else {
    throw new Error("Brak invoiceReferenceNumber lub ksefNumber do pobrania UPO");
  }

  let accept = "application/xml";
  if (prefer === "pdf") accept = "application/pdf";
  if (prefer === "json") accept = "application/json";

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
    upoFileName: isPdf ? "UPO.pdf" : "UPO.xml",
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

    const result = await callKsef(endpoint, accessToken, {
      method: "POST",
      body: rawBody
    });

    const invoiceReferenceNumber = extractInvoiceReferenceNumberFromSendResponse(result.body);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint,
      xmlCharLength: xmlText.length,
      xmlByteLength: encrypted.xmlBuffer.length,
      requestPayload: payload,
      rawRequestBody: rawBody,
      rawRequestBodyLength: Buffer.byteLength(rawBody, "utf8"),
      ksefStatus: result.status,
      invoiceReferenceNumber,
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

    const invoiceReferenceNumber = extractInvoiceReferenceNumberFromSendResponse(result.body);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint,
      requestPayload: payload,
      rawRequestBody: rawBody,
      rawRequestBodyLength: Buffer.byteLength(rawBody, "utf8"),
      ksefStatus: result.status,
      invoiceReferenceNumber,
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
    const duplicateInfo = extractDuplicateInfoFromFailedResponse(result.body);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint: result.endpoint,
      ksefStatus: result.status,
      isDuplicate: duplicateInfo.isDuplicate,
      duplicateStatusCode: duplicateInfo.duplicateStatusCode,
      duplicateStatusDescription: duplicateInfo.duplicateStatusDescription,
      originalKsefNumber: duplicateInfo.originalKsefNumber,
      originalSessionReferenceNumber: duplicateInfo.originalSessionReferenceNumber,
      originalInvoiceNumber: duplicateInfo.originalInvoiceNumber,
      originalReferenceNumber: duplicateInfo.originalReferenceNumber,
      duplicateFailedInvoice: duplicateInfo.duplicateFailedInvoice,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /session-failed error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/invoice-status", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");
    const invoiceReferenceNumber = requireString(body, "invoiceReferenceNumber");

    const result = await getInvoiceStatus(accessToken, sessionReferenceNumber, invoiceReferenceNumber);

    const invoiceObj =
      result.body?.invoice ||
      result.body?.ksefResponse?.invoice ||
      result.body?.response?.invoice ||
      result.body;

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint: result.endpoint,
      ksefStatus: result.status,
      invoiceReferenceNumber: extractReferenceNumber(invoiceObj) || invoiceReferenceNumber,
      ksefNumber: extractKsefNumber(invoiceObj),
      invoiceStatus: extractInvoiceStatus(invoiceObj),
      acquisitionTimestamp: extractAcquisitionTimestamp(invoiceObj),
      invoice: invoiceObj,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /invoice-status error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/invoice-upo", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");
    const invoiceReferenceNumber = optionalString(body, "invoiceReferenceNumber", "");
    const ksefNumber = optionalString(body, "ksefNumber", "");
    const prefer = optionalString(body, "prefer", "xml");

    const result = await getInvoiceUpo(accessToken, sessionReferenceNumber, {
      invoiceReferenceNumber,
      ksefNumber,
      prefer
    });

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

app.post("/finalize-session", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");
    const invoiceReferenceNumber = requireString(body, "invoiceReferenceNumber");
    const closeAfter = optionalBoolean(body, "closeAfter", true);
    const pollCount = optionalNumber(body, "pollCount", 5);
    const pollDelayMs = optionalNumber(body, "pollDelayMs", 1000);
    const preferUpo = optionalString(body, "preferUpo", "xml");

    let statusResult = null;
    let summary = null;

    for (let i = 0; i < pollCount; i++) {
      statusResult = await getSessionStatus(accessToken, sessionReferenceNumber);
      summary = extractSessionSummary(statusResult.body);

      if (summary.failedInvoiceCount > 0 || summary.successfulInvoiceCount > 0 || summary.invoiceCount > 0) {
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
      const duplicateInfo = extractDuplicateInfoFromFailedResponse(failedResult.body);

      let closeResult = null;
      if (closeAfter) {
        closeResult = await closeSession(accessToken, sessionReferenceNumber);
      }

      return res.status(200).json({
        ok: duplicateInfo.isDuplicate,
        processed: true,
        accepted: false,
        isDuplicate: duplicateInfo.isDuplicate,
        sessionReferenceNumber,
        invoiceReferenceNumber,
        sessionStatusCode: summary.statusCode,
        sessionStatusDescription: summary.statusDescription,
        invoiceCount: summary.invoiceCount,
        successfulInvoiceCount: summary.successfulInvoiceCount,
        failedInvoiceCount: summary.failedInvoiceCount,
        duplicateStatusCode: duplicateInfo.duplicateStatusCode,
        duplicateStatusDescription: duplicateInfo.duplicateStatusDescription,
        originalKsefNumber: duplicateInfo.originalKsefNumber,
        originalSessionReferenceNumber: duplicateInfo.originalSessionReferenceNumber,
        originalInvoiceNumber: duplicateInfo.originalInvoiceNumber,
        originalReferenceNumber: duplicateInfo.originalReferenceNumber,
        failedResponse: failedResult.body,
        closeAttempted: closeAfter,
        closeResponse: closeResult
          ? {
              endpoint: closeResult.endpoint,
              httpStatus: closeResult.status,
              response: closeResult.body
            }
          : null,
        message: duplicateInfo.isDuplicate
          ? "Faktura już wcześniej istnieje w KSeF (duplikat)"
          : "Sesja zawiera błędne faktury"
      });
    }

    let invoiceStatusResult = null;
    let invoiceObj = null;

    for (let i = 0; i < pollCount; i++) {
      invoiceStatusResult = await getInvoiceStatus(
        accessToken,
        sessionReferenceNumber,
        invoiceReferenceNumber
      );

      const bodyObj = invoiceStatusResult.body;

      if (invoiceStatusResult.ok) {
        invoiceObj =
          bodyObj?.invoice ||
          bodyObj?.ksefResponse?.invoice ||
          bodyObj?.response?.invoice ||
          bodyObj;
      }

      const ksefNumber = extractKsefNumber(invoiceObj);
      if (ksefNumber) {
        break;
      }

      if (i < pollCount - 1) {
        await sleep(pollDelayMs);
      }
    }

    let closeResult = null;
    if (closeAfter) {
      closeResult = await closeSession(accessToken, sessionReferenceNumber);
    }

    if (!invoiceStatusResult || !invoiceStatusResult.ok) {
      return res.status(200).json({
        ok: false,
        processed: true,
        accepted: false,
        isDuplicate: false,
        sessionReferenceNumber,
        invoiceReferenceNumber,
        sessionStatusCode: summary.statusCode,
        sessionStatusDescription: summary.statusDescription,
        invoiceCount: summary.invoiceCount,
        successfulInvoiceCount: summary.successfulInvoiceCount,
        failedInvoiceCount: summary.failedInvoiceCount,
        invoiceStatusEndpoint: invoiceStatusResult?.endpoint || "",
        invoiceStatusHttpStatus: invoiceStatusResult?.status || 0,
        invoiceStatusResponse: invoiceStatusResult?.body || null,
        invoiceStatusError: extractSuccessfulEndpointError(invoiceStatusResult?.body || {}),
        closeAttempted: closeAfter,
        closeResponse: closeResult
          ? {
              endpoint: closeResult.endpoint,
              httpStatus: closeResult.status,
              response: closeResult.body
            }
          : null,
        message: "Nie udało się pobrać statusu faktury z sesji"
      });
    }

    const referenceNumber = extractReferenceNumber(invoiceObj) || invoiceReferenceNumber;
    const ksefNumber = extractKsefNumber(invoiceObj);
    const invoiceStatus = extractInvoiceStatus(invoiceObj);
    const acquisitionTimestamp = extractAcquisitionTimestamp(invoiceObj);

    let upoResult = null;
    let upoReady = false;

    if (ksefNumber || referenceNumber) {
      try {
        upoResult = await getInvoiceUpo(accessToken, sessionReferenceNumber, {
          invoiceReferenceNumber: referenceNumber,
          ksefNumber,
          prefer: preferUpo
        });

        if (upoResult && upoResult.status >= 200 && upoResult.status < 300) {
          upoReady = true;
        }
      } catch (e) {
        console.error("UPO fetch error:", e);
      }
    }

    return res.status(200).json({
      ok: true,
      processed: Boolean(ksefNumber),
      accepted: Boolean(ksefNumber),
      isDuplicate: false,
      sessionReferenceNumber,
      invoiceReferenceNumber: referenceNumber,
      ksefNumber,
      invoiceStatus,
      acquisitionTimestamp,
      sessionStatusCode: summary.statusCode,
      sessionStatusDescription: summary.statusDescription,
      invoiceCount: summary.invoiceCount,
      successfulInvoiceCount: summary.successfulInvoiceCount,
      failedInvoiceCount: summary.failedInvoiceCount,
      invoiceStatusEndpoint: invoiceStatusResult.endpoint,
      invoiceStatusHttpStatus: invoiceStatusResult.status,
      selectedInvoice: invoiceObj,
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
      message: ksefNumber
        ? "Faktura przyjęta; pobrano numer KSeF"
        : "Faktura jeszcze przetwarzana, brak numeru KSeF"
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
