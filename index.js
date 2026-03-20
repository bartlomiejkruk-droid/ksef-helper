import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "1mb" }));

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

  if (!Array.isArray(data?.certificates)) {
    throw new Error(`Unexpected certificates response: ${JSON.stringify(data)}`);
  }

  const certObj = data.certificates.find(c =>
    Array.isArray(c.usage) && c.usage.includes("KsefTokenEncryption")
  );

  if (!certObj) {
    throw new Error("No KsefTokenEncryption certificate found");
  }

  const certPem = certObj.certificate;
  if (!certPem || typeof certPem !== "string") {
    throw new Error("Certificate PEM missing");
  }

  const publicKey = crypto.createPublicKey(certPem).export({
    type: "spki",
    format: "pem"
  });

  return publicKey.toString();
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
