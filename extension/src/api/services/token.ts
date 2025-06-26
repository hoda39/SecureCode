import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });

export class TokenService {
  static generateAuthToken(userId: string, role: 'admin' | 'user'): string {
    return jwt.sign(
      { 
        id: userId,
        role: role,
        iat: Math.floor(Date.now() / 1000)
      },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' }
    );
  }

  static generateAnalysisToken(): string {
    return uuidv4(); // Generate a new UUID (Universally Unique Identifier)
  }
}
