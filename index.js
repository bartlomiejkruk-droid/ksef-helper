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

// 1) Encrypt token
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

// 2) Session encryption
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

// 3) Encrypt document (debug / test)
app.post("/encrypt-document", async (req, res) => {
  try {
    const { xmlText, aesKeyBase64, initializationVector } = req.body;

    const invoiceBuffer = Buffer.from(xmlText, "utf8");
    const aesKey = Buffer.from(aesKeyBase64, "base64");
    const iv = Buffer.from(initializationVector, "base64");

    const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
    const cipherText = Buffer.concat([
      cipher.update(invoiceBuffer),
      cipher.final()
    ]);

    const encryptedBuffer = Buffer.concat([iv, cipherText]);

    return res.json({
      invoiceHash: sha256Base64(invoiceBuffer),
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

// 4) SEND INVOICE (FINAL)
app.post("/send-invoice", async (req, res) => {
  try {
    const {
      accessToken,
      sessionReferenceNumber,
      xmlText,
      aesKeyBase64,
      initializationVector
    } = req.body;

    const invoiceBuffer = Buffer.from(xmlText, "utf8");
    const aesKey = Buffer.from(aesKeyBase64, "base64");
    const iv = Buffer.from(initializationVector, "base64");

    const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
    const cipherText = Buffer.concat([
      cipher.update(invoiceBuffer),
      cipher.final()
    ]);

    // KLUCZOWE — IV NA POCZĄTKU
    const encryptedBuffer = Buffer.concat([iv, cipherText]);

    const payload = {
      invoiceHash: sha256Base64(invoiceBuffer),
      invoiceSize: invoiceBuffer.length,
      encryptedDocumentHash: sha256Base64(encryptedBuffer),
      encryptedDocumentSize: encryptedBuffer.length,
      encryptedDocumentContent: encryptedBuffer.toString("base64")
    };

    const rawBody = JSON.stringify(payload);

    const ksefResp = await fetch(
      `https://api-test.ksef.mf.gov.pl/v2/sessions/online/${sessionReferenceNumber}/invoices`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": "application/json",
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
      requestPayload: payload,
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
