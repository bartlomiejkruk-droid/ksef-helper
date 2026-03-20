import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

// WSTAW TU PRAWDZIWY TESTOWY KLUCZ PUBLICZNY KSeF
const publicKeyPem = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvu7G7yEgmEYBLETymFcp`;

app.post("/", (req, res) => {
  try {
    const plainText = req.body.plainText;

    if (!plainText || typeof plainText !== "string") {
      return res.status(400).json({ error: "Brak plainText" });
    }

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
    return res.status(500).json({ error: e.message });
  }
});

app.listen(process.env.PORT || 3000);
