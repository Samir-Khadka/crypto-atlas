// True positives: every JS rule fires on this file.
const crypto = require("crypto");
const tls = require("tls");

// rule 1: RSA key generation (2048 -> weakness 4)
const { publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
// rule 1: RSA key generation, too small (1024 -> weakness 5)
const small = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
// rule 2: ECC key generation (P-256 -> weakness 4)
const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
// rule 3: weak hash
const d = crypto.createHash("md5").update("hello").digest("hex");
const d2 = crypto.createHash("sha1").update("hello").digest("hex");
// rule 4: weak cipher (ECB)
const cipher = crypto.createCipheriv("aes-128-ecb",
  Buffer.alloc(16), Buffer.alloc(16));
// rule 5: weak randomness for a secret
const token = Math.random().toString(36);
// rule 7: TLS verification disabled
const sock = tls.connect({ host: "example.com",
  rejectUnauthorized: false });
const sock2 = tls.connect({ host: "example.com",
  minVersion: "TLSv1" });
