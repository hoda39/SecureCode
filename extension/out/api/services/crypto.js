"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoService = void 0;
const crypto_1 = __importDefault(require("crypto"));
class CryptoService {
    static ALGORITHM = 'aes-256-cbc';
    static encrypt(data, key) {
        if (key.length !== 32)
            throw new Error('Invalid key length');
        const iv = crypto_1.default.randomBytes(16);
        const cipher = crypto_1.default.createCipheriv(this.ALGORITHM, key, iv);
        const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
        return {
            iv: iv.toString('hex'),
            encrypted: encrypted.toString('hex')
        };
    }
    static decrypt(encrypted, key, iv) {
        try {
            // Validate key length (32 bytes required for AES-256-cbc)
            if (key.length !== 32) {
                throw new Error(`Invalid key length: ${key.length} bytes (required: 32)`);
            }
            // Convert IV from hex to Buffer and validate its length
            const ivBuffer = Buffer.from(iv, 'hex');
            if (ivBuffer.length !== 16) {
                throw new Error('IV must be 16 bytes');
            }
            const decipher = crypto_1.default.createDecipheriv(this.ALGORITHM, key, ivBuffer);
            return Buffer.concat([
                decipher.update(Buffer.from(encrypted, 'hex')),
                decipher.final()
            ]).toString('utf8');
        }
        catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }
}
exports.CryptoService = CryptoService;
//# sourceMappingURL=crypto.js.map