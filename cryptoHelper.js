// cryptoHelper.js
const crypto = require('crypto');

// IMPORTANT: Keep this key secret and secure. Store it in your .env file.
// It MUST be 32 characters long for AES-256.
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; 
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // For AES, this is always 16

function encrypt(text) {
    if (!text) return null;
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, 
Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    // Prepend IV and AuthTag to the encrypted data for decryption
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + 
encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return null;
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const authTag = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        
        const decipher = crypto.createDecipheriv(ALGORITHM, 
Buffer.from(ENCRYPTION_KEY), iv);
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString();
    } catch (err) {
        console.error("Decryption failed:", err.message);
        // If decryption fails, it might be an old, unencrypted message.
        // Or it could be a sign of tampering.
        return text; 
    }
}

module.exports = { encrypt, decrypt };
