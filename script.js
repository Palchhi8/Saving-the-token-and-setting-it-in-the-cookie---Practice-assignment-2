const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const SECRET_KEY = 'your_secret_key'; // Replace with a strong secret key
const ENCRYPTION_KEY = crypto.randomBytes(32); // 256-bit key for AES encryption
const IV = crypto.randomBytes(16); // Initialization vector for AES

const encrypt = (payload) => {
    try {
        // Create a JWT token with expiry
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });
        
        // Encrypt the JWT token
        const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
        let encrypted = cipher.update(token, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return `${IV.toString('hex')}:${encrypted}`;
    } catch (error) {
        console.error('Encryption Error:', error);
        return null;
    }
};

const decrypt = (encryptedToken) => {
    try {
        const [ivHex, encrypted] = encryptedToken.split(':');
        const ivBuffer = Buffer.from(ivHex, 'hex');
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, ivBuffer);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return jwt.verify(decrypted, SECRET_KEY);
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            console.error('Token has expired');
        } else {
            console.error('Decryption Error:', error);
        }
        return null;
    }
};

module.exports = {
    encrypt,
    decrypt
};
