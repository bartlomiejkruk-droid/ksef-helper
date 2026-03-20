import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "1mb" }));

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
    throw new Error(`Unexpected certificates response type: ${JSON.stringify(data)}`);
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

app.get("/", (req, res) => {
  res.json({ ok: true, message: "ksef-helper works" });
});

// helper do encryptedToken auth
app.post("/encrypt-token", async (req, res) => {
  try {
    const plainText = req.body.plainText;
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

// helper do sesji online
app.post("/session-encryption", async (req, res) => {
  try {
    const publicKeyPem = await getKsefPublicKeyByUsage("SymmetricKeyEncryption");

    const aesKey = crypto.randomBytes(32); // 256 bit
    const iv = crypto.randomBytes(16);     // 128 bit

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
