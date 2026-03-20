import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "1mb" }));

const publicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvu7G7yEgmEYBLETymFcp
nczHxVn9Yx8RJWb1x1o1t4bm/FYnGV8eK3opgDdGztqKqRR3YKHy+XapnwYfJOLw
Aun1vDLteA94ppIqhzyapMI2vlA38nSxrdbidKdvUSsfx8bVsgcuyo6edSxnl2xe
Tzw9uQWGWpZJYG1ChcxrFAxo0xO+ogzAm8h1Hn0SI7RyhokW2N7DbStO2Qe6hwMR
YB9H9n1tFoZT3zh0+BTtPlqvGjufH6G+jD/adJzi10BGSAdoo6gWQBaIj++ImQx0
dQc5sKXc5teLoI0lp4rWuIwoMvV7bgidh+NROm4tW7x1YgnPZXoqBYwygJyI072z
JQIDAQAB
-----END PUBLIC KEY-----`;

app.get("/", (req, res) => {
  res.json({ ok: true, message: "ksef-helper works" });
});

app.post("/", (req, res) => {
  try {
    const plainText = req.body.plainText;

    if (!plainText || typeof plainText !== "string") {
      return res.status(400).json({
        error: "Brak plainText"
      });
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

    return res.json({
      encryptedToken
    });
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
