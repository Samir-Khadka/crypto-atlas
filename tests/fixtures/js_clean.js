// Clean: good patterns and known false-positive traps. Zero findings.
const crypto = require("crypto");

// good: SHA-256, AES-GCM, randomBytes, a default TLS context
const d = crypto.createHash("sha256").update("hello").digest("hex");
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
// trap: Math.random used for a UI animation, not a secret
const jitter = Math.random() * 100;
