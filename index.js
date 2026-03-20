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

async function getKsefTokenEncryptionPublicKey() {
  const resp = await fetch("https://api-test.ksef.mf.gov.pl/v2/security/public-key-certificates", {
    method: "GET",
    headers: {
      "Accept": "application/json"
    }
  });

  if (!resp.ok) {
    throw new Error(`KSeF cert fetch failed: ${resp.status}`);
  }

  const data = await resp.json();

  // Endpoint zwraca TABLICĘ, nie { certificates: [...] }
  if (!Array.isArray(data)) {
    throw new Error(`Unexpected certificates response type: ${JSON.stringify(data)}`);
  }

  const certObj = data.find(c =>
    Array.isArray(c.usage) && c.usage.includes("KsefTokenEncryption")
  );

  if (!certObj) {
    throw new Error("No KsefTokenEncryption certificate found");
  }

  if (!certObj.certificate || typeof certObj.certificate !== "string") {
    throw new Error("Certificate value missing");
  }

  const certPem = toPemCertificate(certObj.certificate);

  // Wyciągnięcie public key z certyfikatu X.509
  const x509 = new crypto.X509Certificate(certPem);
  const publicKeyPem = x509.publicKey.export({
    type: "spki",
    format: "pem"
  }).toString();

  return publicKeyPem;
}

app.get("/", (req, res) => {
  res.json({ ok: true, message: "ksef-helper works" });
});

app.post("/", async (req, res) => {
  try {
    const plainText = req.body.plainText;

    if (!plainText || typeof plainText !== "string") {
      return res.status(400).json({ error: "Brak plainText" });
    }

    const publicKeyPem = await getKsefTokenEncryptionPublicKey();

    const encryptedBuffer = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(plainText, "utf8")
    );

    const encryptedToken = encryptedBuffer.toString("base64");

    return res.json({ encryptedToken });
  } catch (e) {
    console.error("POST / error:", e);
    return res.status(500).json({
      error: e.message
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
