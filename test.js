const { encrypt, decrypt } = require('./script');

const payload = { userId: 123, role: 'admin' };

// Encrypt the JWT token
const encryptedToken = encrypt(payload);
console.log('🔒 Encrypted Token:', encryptedToken);

// Wait for a moment, then decrypt
setTimeout(() => {
    const decryptedPayload = decrypt(encryptedToken);
    if (decryptedPayload) {
        console.log('✅ Decrypted Payload:', decryptedPayload);
    } else {
        console.log('❌ Decryption failed or token expired');
    }
}, 2000); // Adjust timeout if testing expiry
