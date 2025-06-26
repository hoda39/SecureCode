import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });

interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: 'admin' | 'user'; // Add role field
}

export class UserService {
  private static users: User[] = []; // In production, use a database

  static getUserCount(): number {
    return this.users.length;
  }

  static async authenticate(username: string, password: string): Promise<User> {
    const user = this.users.find(u => u.username === username);
    if (!user) throw new Error('User not found');
    
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) throw new Error('Invalid password');
    
    return user;
  }

  static async createUser(username: string, password: string, requesterId?: string): Promise<User> {
    // If a requesterId is provided, ensure the requester exists and is an admin
    // NEW: Skip admin check in local mode
    if (process.env.AUTH_MODE !== 'local' && requesterId) {
      // Existing admin validation
      const requester = this.users.find(u => u.id === requesterId);
      if (!requester || requester.role !== 'admin') {
        throw new Error('Admin privileges required');
      }
    }
  
    // Check if the username already exists
    const exists = this.users.some(u => u.username === username);
    if (exists) throw new Error('User already exists');
  
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
  
    // NEW: First user is always admin regardless of mode
    const isFirstUser = this.users.length === 0;
    const newUser: User = {
      id: uuidv4(),
      username,
      passwordHash,
      role: isFirstUser ? 'admin' : 'user'
    };
  
    this.users.push(newUser);
    return newUser;
  }  

  static async listUsers(): Promise<User[]> {
    return this.users.map(u => ({ ...u, passwordHash: 'undefined' }));
  }
}