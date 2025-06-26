import crypto from 'crypto';

export class CryptoService {
  private static ALGORITHM = 'aes-256-cbc';

  static encrypt(data: string, key: Buffer): { iv: string; encrypted: string } {
    if (key.length !== 32) throw new Error('Invalid key length');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    
    return {
      iv: iv.toString('hex'),
      encrypted: encrypted.toString('hex')
    };
  }

  static decrypt(encrypted: string, key: Buffer, iv: string): string {
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

      const decipher = crypto.createDecipheriv(this.ALGORITHM, key, ivBuffer);
      return Buffer.concat([
        decipher.update(Buffer.from(encrypted, 'hex')),
        decipher.final()
      ]).toString('utf8');
    } catch (error: any) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }
}
