import express from "express";
import crypto from "crypto";

const app = express();

app.use(express.json({ limit: "20mb" }));
app.use(express.text({ type: ["text/*", "application/*"], limit: "20mb" }));

const KSEF_BASE_URL = process.env.KSEF_BASE_URL || "https://api-demo.ksef.mf.gov.pl";
const PORT = process.env.PORT || 3000;

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

function requirePositiveNumber(obj, key) {
  const value = Number(obj[key]);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Brak lub błędne pole liczbowe: ${key}`);
  }
  return value;
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

  // KLUCZOWA ZMIANA:
  // NIE dokładamy IV do encryptedInvoiceContent
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

async function callKsef(url, accessToken, options = {}) {
  const resp = await fetch(url, {
    method: options.method || "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {})
    },
    ...(options.body ? { body: options.body } : {})
  });

  const text = await resp.text();

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }

  return {
    status: resp.status,
    ok: resp.ok,
    body: parsed,
    raw: text
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
    const endpoint = `${KSEF_BASE_URL}/v2/sessions/online/${sessionReferenceNumber}/invoices`;

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

app.post("/session-status", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");

    const endpoint = `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}`;
    const result = await callKsef(endpoint, accessToken);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint,
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

    const endpoint = `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/failed`;
    const result = await callKsef(endpoint, accessToken);

    return res.status(result.status).json({
      baseUrl: KSEF_BASE_URL,
      endpoint,
      ksefStatus: result.status,
      ksefResponse: result.body
    });
  } catch (e) {
    console.error("POST /session-failed error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/session-debug", async (req, res) => {
  try {
    const body = safeParseBody(req);

    const accessToken = requireString(body, "accessToken");
    const sessionReferenceNumber = requireString(body, "sessionReferenceNumber");

    const statusEndpoint = `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}`;
    const failedEndpoint = `${KSEF_BASE_URL}/v2/sessions/${sessionReferenceNumber}/invoices/failed`;

    const [statusResult, failedResult] = await Promise.all([
      callKsef(statusEndpoint, accessToken),
      callKsef(failedEndpoint, accessToken)
    ]);

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
      }
    });
  } catch (e) {
    console.error("POST /session-debug error:", e);
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
    const endpoint = `${KSEF_BASE_URL}/v2/sessions/online/${sessionReferenceNumber}/invoices`;

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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`KSEF_BASE_URL=${KSEF_BASE_URL}`);
});
