<?php
header('Content-Type: application/json');

$data = json_decode(file_get_contents("php://input"), true);

$plaintext = $data["token"] . "|" . $data["timestamp"];

$publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYQy0nF6BqF9t7VDaRao
IhiHBpjz2uVH54camzatoNgtrENcGukdxbYlR5c+3F4iAfDdc0AGJi/7luWGINuD
7++UZ5EONosFVJeFt3PcTJS3BM4tiTqcKoy0eZZ+j9RnBbTK1ZBOqVakiobP6KyL
Y6z3Y0JVpaz6RtWLpmjHtkobaN6D+PfYZ7RUTpujISiFDUFxIr05oig3NbS1RyYP
F7kKIhxX3sI5Yucs5cjox96D65gis6pZeRAEIJ5zsxFrqxbPjzvY4xXHzkwmo7aX
ixkmKuuNHYsYvwdivgLPgAvFp8ZUBKbjsgg7sWXBJgp7wa9u0edPFsKnz03Wx/ju
RwIDAQAB
-----END PUBLIC KEY-----
EOD;

openssl_public_encrypt($plaintext,$encrypted,$publicKey,OPENSSL_PKCS1_OAEP_PADDING);

echo json_encode([
 "encryptedToken"=>base64_encode($encrypted)
]);
