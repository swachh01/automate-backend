const crypto = require('crypto');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;

// Fail fast at boot instead of at the first encrypt() call. A missing or
// wrong-length key otherwise surfaces as a confusing runtime crash deep in
// some unrelated request.
if (!ENCRYPTION_KEY) {
    throw new Error('ENCRYPTION_KEY environment variable is not set');
}
if (Buffer.from(ENCRYPTION_KEY).length !== 32) {
    throw new Error(
        `ENCRYPTION_KEY must be 32 bytes for ${ALGORITHM} (got ${Buffer.from(ENCRYPTION_KEY).length} bytes)`
    );
}

// True only for strings shaped like our own iv:authTag:ciphertext output
// (32 hex chars for a 16-byte IV, 32 hex chars for a 16-byte auth tag).
// Used to tell "this was never encrypted" (legacy plaintext) apart from
// "this was encrypted but failed to decrypt" (tampered/corrupted).
function looksEncrypted(text) {
    const parts = text.split(':');
    if (parts.length < 3) return false;
    const [ivHex, tagHex] = parts;
    return /^[0-9a-f]{32}$/i.test(ivHex) && /^[0-9a-f]{32}$/i.test(tagHex);
}

function encrypt(text, aad) {
    if (!text) return null;
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    // Optional: bind this ciphertext to a context (e.g. a row id) so it
    // can't be silently swapped with another row's ciphertext and still
    // decrypt successfully. Must pass the same aad value to decrypt().
    if (aad) cipher.setAAD(Buffer.from(String(aad)));
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' +
encrypted.toString('hex');
}

function decrypt(text, aad) {
    if (!text) return null;

    if (!looksEncrypted(text)) {
        // Doesn't match our iv:authTag:ciphertext shape at all — treat as
        // legacy pre-encryption plaintext, not a decryption failure.
        return text;
    }

    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const authTag = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');

        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
        decipher.setAuthTag(authTag);
        if (aad) decipher.setAAD(Buffer.from(String(aad)));

        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted.toString();
    } catch (err) {
        // This looked like our ciphertext format but failed GCM
        // authentication — i.e. it was tampered with, corrupted, or
        // encrypted/decrypted with mismatched AAD. Do NOT hand the raw
        // hex-looking blob back to the caller as if it were valid content;
        // callers need to catch this and decide how to surface it.
        console.error("Decryption failed integrity check:", err.message);
        throw new Error("Failed to decrypt: data may be corrupted or tampered with");
    }
}

module.exports = { encrypt, decrypt };
