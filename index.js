const http = require("http");
const https = require("https");
const crypto = require("crypto");

function derBase64ToPemCertificate(derBase64) {
  const lines = derBase64.match(/.{1,64}/g) || [];
  return [
    "-----BEGIN CERTIFICATE-----",
    ...lines,
    "-----END CERTIFICATE-----"
  ].join("\n");
}

function fetchCurrentCertificate() {
  return new Promise((resolve, reject) => {
    https.get("https://api-test.ksef.mf.gov.pl/v2/security/public-key-certificates", (res) => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => {
        try {
          const arr = JSON.parse(data);
          const cert = arr.find(x => Array.isArray(x.usage) && x.usage.includes("KsefTokenEncryption"));
          if (!cert) {
            return reject(new Error("Brak certyfikatu KsefTokenEncryption"));
          }
          resolve(derBase64ToPemCertificate(cert.certificate));
        } catch (e) {
          reject(e);
        }
      });
    }).on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Method not allowed" }));
  }

  let body = "";
  req.on("data", chunk => body += chunk.toString());

  req.on("end", async () => {
    try {
      const data = JSON.parse(body);

      if (!data.token || !data.timestamp) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Brak token albo timestamp" }));
      }

      const pemCert = await fetchCurrentCertificate();

      const plaintext = `${data.token}|${data.timestamp}`;

      const encrypted = crypto.publicEncrypt(
        {
          key: pemCert,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        Buffer.from(plaintext, "utf8")
      );

      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({
        encryptedToken: encrypted.toString("base64")
      }));
    } catch (e) {
      res.writeHead(500, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: e.message }));
    }
  });
});

const port = process.env.PORT || 3000;
server.listen(port, "0.0.0.0");
