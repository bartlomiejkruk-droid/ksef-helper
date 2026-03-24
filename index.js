import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "15mb" }));

function toPemCertificate(base64Cert) {
  const lines = base64Cert.match(/.{1,64}/g)?.join("\n") || base64Cert;
  return `-----BEGIN CERTIFICATE-----
${lines}
-----END CERTIFICATE-----`;
}

async function getKsefPublicKeyByUsage(requiredUsage) {
  const resp = await fetch("https://api-test.ksef.mf.gov.pl/v2/security/public-key-certificates", {
    method: "GET",
    headers: { "Accept": "application/json" }
  });

  if (!resp.ok) {
    throw new Error(`KSeF cert fetch failed: ${resp.status}`);
  }

  const data = await resp.json();

  if (!Array.isArray(data)) {
    throw new Error(`Unexpected certificates response type`);
  }

  const certObj = data.find(c =>
    Array.isArray(c.usage) && c.usage.includes(requiredUsage)
  );

  if (!certObj?.certificate) {
    throw new Error(`No certificate found for usage ${requiredUsage}`);
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

app.get("/", (req, res) => {
  res.json({ ok: true, message: "ksef-helper works" });
});

app.post("/encrypt-token", async (req, res) => {
  try {
    const { plainText } = req.body;

    if (!plainText || typeof plainText !== "string") {
      return res.status(400).json({ error: "Brak plainText" });
    }

    const publicKeyPem = await getKsefPublicKeyByUsage("KsefTokenEncryption");

    const encryptedBuffer = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
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
        oaepHash: "sha256",
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
    const { xmlText, aesKeyBase64, initializationVector } = req.body;

    const invoiceBuffer = Buffer.from(xmlText, "utf8");
    const aesKey = Buffer.from(aesKeyBase64, "base64");
    const iv = Buffer.from(initializationVector, "base64");

    if (aesKey.length !== 32) {
      return res.status(400).json({ error: "AES key must be 32 bytes" });
    }
    if (iv.length !== 16) {
      return res.status(400).json({ error: "IV must be 16 bytes" });
    }

    const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
    const cipherText = Buffer.concat([
      cipher.update(invoiceBuffer),
      cipher.final()
    ]);

    const encryptedBuffer = Buffer.concat([iv, cipherText]);

    return res.json({
      fileHash: sha256Base64(invoiceBuffer),
      invoiceHash: sha256Base64(invoiceBuffer),
      fileSize: invoiceBuffer.length,
      invoiceSize: invoiceBuffer.length,
      encryptedDocumentHash: sha256Base64(encryptedBuffer),
      encryptedDocumentSize: encryptedBuffer.length,
      encryptedDocumentContent: encryptedBuffer.toString("base64")
    });
  } catch (e) {
    console.error("POST /encrypt-document error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post("/send-invoice", async (req, res) => {
  try {
    const {
      accessToken,
      sessionReferenceNumber,
      xmlText,
      aesKeyBase64,
      initializationVector
    } = req.body;

    if (!accessToken || typeof accessToken !== "string") {
      return res.status(400).json({ error: "Brak accessToken" });
    }
    if (!sessionReferenceNumber || typeof sessionReferenceNumber !== "string") {
      return res.status(400).json({ error: "Brak sessionReferenceNumber" });
    }
    if (!xmlText || typeof xmlText !== "string") {
      return res.status(400).json({ error: "Brak xmlText" });
    }
    if (!aesKeyBase64 || typeof aesKeyBase64 !== "string") {
      return res.status(400).json({ error: "Brak aesKeyBase64" });
    }
    if (!initializationVector || typeof initializationVector !== "string") {
      return res.status(400).json({ error: "Brak initializationVector" });
    }

    const invoiceBuffer = Buffer.from(xmlText, "utf8");
    const aesKey = Buffer.from(aesKeyBase64, "base64");
    const iv = Buffer.from(initializationVector, "base64");

    if (aesKey.length !== 32) {
      return res.status(400).json({ error: "AES key must be 32 bytes" });
    }
    if (iv.length !== 16) {
      return res.status(400).json({ error: "IV must be 16 bytes" });
    }

    const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
    const cipherText = Buffer.concat([
      cipher.update(invoiceBuffer),
      cipher.final()
    ]);

    const encryptedBuffer = Buffer.concat([iv, cipherText]);

    const plainHash = sha256Base64(invoiceBuffer);

    const payload = {
      fileHash: plainHash,
      invoiceHash: plainHash,
      fileSize: invoiceBuffer.length,
      invoiceSize: invoiceBuffer.length,
      encryptedDocumentHash: sha256Base64(encryptedBuffer),
      encryptedDocumentSize: encryptedBuffer.length,
      encryptedDocumentContent: encryptedBuffer.toString("base64")
    };

    const rawBody = JSON.stringify(payload);

console.log("=== FINAL CHECK ===");
console.log("fileHash:", payload.fileHash);
console.log("rawBody contains fileHash:", rawBody.includes("fileHash"));
console.log("rawBody:", rawBody);
console.log("rawBody length:", Buffer.byteLength(rawBody, "utf8"));

const ksefResp = await fetch(
  `https://api-test.ksef.mf.gov.pl/v2/sessions/online/${sessionReferenceNumber}/invoices`,
  {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/json; charset=utf-8", // 🔴 DODAJ TO
      "Accept": "application/json"
    },
    body: rawBody
  }
);

    const text = await ksefResp.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text };
    }

    return res.status(ksefResp.status).json({
      xmlCharLength: xmlText.length,
      xmlByteLength: invoiceBuffer.length,
      requestPayload: payload,
      rawRequestBody: rawBody,
      rawRequestBodyLength: Buffer.byteLength(rawBody, "utf8"),
      ksefStatus: ksefResp.status,
      ksefResponse: parsed
    });
  } catch (e) {
    console.error("POST /send-invoice error:", e);
    return res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
