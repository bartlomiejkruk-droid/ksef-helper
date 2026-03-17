const http = require('http');
const crypto = require('crypto');

const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYQy0nF6BqF9t7VDaRao
IhiHBpjz2uVH54camzatoNgtrENcGukdxbYlR5c+3F4iAfDdc0AGJi/7luWGINuD
7++UZ5EONosFVJeFt3PcTJS3BM4tiTqcKoy0eZZ+j9RnBbTK1ZBOqVakiobP6KyL
Y6z3Y0JVpaz6RtWLpmjHtkobaN6D+PfYZ7RUTpujISiFDUFxIr05oig3NbS1RyYP
F7kKIhxX3sI5Yucs5cjox96D65gis6pZeRAEIJ5zsxFrqxbPjzvY4xXHzkwmo7aX
ixkmKuuNHYsYvwdivgLPgAvFp8ZUBKbjsgg7sWXBJgp7wa9u0edPFsKnz03Wx/ju
RwIDAQAB
-----END PUBLIC KEY-----`;

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Method not allowed' }));
  }

  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
  });

  req.on('end', () => {
    try {
      const data = JSON.parse(body);

      if (!data.token || !data.timestamp) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Brak token albo timestamp' }));
      }

      const plaintext = `${data.token}|${data.timestamp}`;

      const encrypted = crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        Buffer.from(plaintext, 'utf8')
      );

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        encryptedToken: encrypted.toString('base64')
      }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
  });
});

const port = process.env.PORT || 3000;
server.listen(port, '0.0.0.0');
