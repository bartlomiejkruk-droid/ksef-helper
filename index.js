const http = require("http");
const crypto = require("crypto");

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYQy0nF6BqF9t7VDaRao
IhiHBpjz2uVH54camzatoNgtrENcGukdxbYlR5c+3F4iAfDdc0AGJi/7luWGINuD
7++UZ5EONosFVJeFt3PcTJS3BM4tiTqcKoy0eZZ+j9RnBbTK1ZBOqVakiobP6KyL
Y6z3Y0JVpaz6RtWLpmjHtkobaN6D+PfYZ7RUTpujISiFDUFxIr05oig3NbS1RyYP
F7kKIhxX3sI5Yucs5cjox96D65gis6pZeRAEIJ5zsxFrqxbPjzvY4xXHzkwmo7aX
ixkmKuuNHYsYvwdivgLPgAvFp8ZUBKbjsgg7sWXBJgp7wa9u0edPFsKnz03Wx/ju
RwIDAQAB
-----END PUBLIC KEY-----`;

http.createServer((req, res) => {

if(req.method !== "POST"){
res.writeHead(405);
return res.end();
}

let body = "";

req.on("data", chunk => body += chunk);

req.on("end", () => {

const data = JSON.parse(body);

const plaintext = `${data.token}|${data.timestamp}`;

const encrypted = crypto.publicEncrypt(
{
key: PUBLIC_KEY,
padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
oaepHash: "sha256"
},
Buffer.from(plaintext)
);

res.writeHead(200, {"Content-Type":"application/json"});
res.end(JSON.stringify({
encryptedToken: encrypted.toString("base64")
}));

});

}).listen(process.env.PORT || 3000);
