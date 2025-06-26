import axios, { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import { CryptoService } from '../api/services/crypto';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as jwt from 'jsonwebtoken';
import * as vscode from 'vscode';
import dotenv from 'dotenv';
import path from 'path';
import https from 'https';

dotenv.config({ path: path.resolve(__dirname, '../../../.env') });


interface SecureAnalysisClientConfig {
  baseURL?: string;
  context: vscode.ExtensionContext;
}

interface AnalysisStatus {
  id: string;
  state: string;
  results?: any;
  error?: string;
  duration: number;
  crashes?: number; // NEW: Add crash count
}

export class AnalysisAPIClient {
  private api: AxiosInstance;
  private encryptionKey!: Buffer;
  private context: vscode.ExtensionContext;

  constructor(config: SecureAnalysisClientConfig) {
    this.context = config.context;
    this.api = axios.create({
      baseURL: 'https://localhost:3000/api', //config.baseURL || process.env.API_BASE_URL ||
      timeout: 300000,
      httpsAgent: new https.Agent({ 
        rejectUnauthorized: false,
        secureOptions: crypto.constants.SSL_OP_NO_SSLv3 |
                       crypto.constants.SSL_OP_NO_TLSv1 |
                       crypto.constants.SSL_OP_NO_TLSv1_1
      }) // Allow self-signed certificates
    });
    // This ensures client keys stay synchronized with server environment variables while maintaining secure storage through VS Code's SecretStorage API.
    setInterval(() => this.validateKeyConsistency(), 3600000); // Check hourly
    // Setup interceptors
    this.api.interceptors.request.use(this.authInterceptor.bind(this));
  }

  /** Initialize security components */
  public async initialize(firstRun: boolean = false): Promise<boolean> {
    this.encryptionKey = await this.getOrCreateEncryptionKey();

    // ADD: Local mode handling
    if (process.env.AUTH_MODE === 'local') {
      // Store fixed token for local mode
      await this.context.secrets.store('authToken', process.env.FIXED_TOKEN!);
      return false; // No first admin created in local mode
    }
    
    let firstAdminCreated = false;
    if (firstRun) {
      firstAdminCreated = await this.handleFirstTimeSetup();
    } else {
      await this.ensureValidAuthToken();
    }
    return firstAdminCreated;
  }

  /** Encrypt and submit file for analysis */
  public async runDynamicAnalysis(filePath: string, abortSignal?: AbortSignal): Promise<string> {
    const fileContent = await fs.promises.readFile(filePath, 'utf-8');
    
    // Encrypt file content and path separately
    const { iv: contentIV, encrypted: encryptedContent } = CryptoService.encrypt(fileContent, this.encryptionKey);
    const { iv: pathIV, encrypted: encryptedPath } = CryptoService.encrypt(filePath, this.encryptionKey);
    
    const response = await this.api.post('/analysis', {
      encryptedContent,
      contentIV,
      encryptedPath,
      pathIV
    }, { 
      signal: abortSignal,
      timeout: 300000
    });
    return response.data.analysisId;
  }

  /** Get analysis status */
  public async getAnalysisStatus(analysisId: string): Promise<AnalysisStatus> {
    const response = await this.api.get(`/analysis/${analysisId}/status`);
    return response.data;
  }

  /** Cancel ongoing analysis */
  public async cancelDynamicAnalysis(analysisId: string): Promise<void> {
    await this.api.delete(`/analysis/${analysisId}/cancel`);
  }

  public async register(username: string, password: string): Promise<void> {
    const response = await this.api.post('/auth/register', { username, password });
    if (response.status !== 201) {
      throw new Error('Registration failed');
    }
  }

  public async login(username: string, password: string): Promise<void> {
    const response = await this.api.post('/auth/login', { username, password });
    const token = response.data.token;

    // Verify token structure before storing
    const decoded = jwt.decode(token) as { id?: string, role?: string };
    if (!decoded?.id || !decoded?.role) {
      throw new Error('Invalid token received from server');
    }

    await this.context.secrets.store('authToken', token);
  }

  public async registerUser(username: string, password: string, role?: 'admin' | 'user'): Promise<void> {
    try {
      const response = await this.api.post('/auth/register', {
        username,
        password,
        role
      });
      
      if (response.status !== 201) {
        throw new Error('User registration failed');
      }
    } catch (error: any) {
      // Extract server error message from response
      const serverMessage = error.response?.data?.error || error.message;
      throw new Error(serverMessage);
    }
  }
  
  public async listUsers(): Promise<any[]> {
    const response = await this.api.get('/auth/users');
    return response.data;
  }

  public isLocalMode(): boolean {
    return process.env.AUTH_MODE === 'local';
  }

  /* Axios request interceptor for auth headers */
  private async authInterceptor(config: InternalAxiosRequestConfig): Promise<InternalAxiosRequestConfig> {
    const token = await this.context.secrets.get('authToken');

    if (token) {
      config.headers.set('Authorization', `Bearer ${token}`);
    }

    return config;
  }

  private async handleFirstTimeSetup(): Promise<boolean> {
    const registered = await this.promptFirstTimeRegistration();
    if (!registered) {
      throw new Error('Initial setup required - create an admin account');
    }
    return true;
  }

  private async promptFirstTimeRegistration(): Promise<boolean> {
    // ADD: Skip in local mode
    if (process.env.AUTH_MODE === 'local') {
      return false;
    }

    const choice = await vscode.window.showInformationMessage(
      'Welcome to Secure Code Analyzer! Create your first admin account:',
      'Create Account', 'Cancel'
    );

    if (choice === 'Create Account') {
      const username = await vscode.window.showInputBox({
        prompt: 'Enter admin username',
        ignoreFocusOut: true
      });
      
      const password = await vscode.window.showInputBox({
        prompt: 'Enter admin password',
        password: true,
        ignoreFocusOut: true
      });

      if (username && password) {
        await this.register(username, password);
        await this.login(username, password);
        return true;
      }
    }
    return false;
  }

  /** Get or generate encryption key */
  private async getOrCreateEncryptionKey(): Promise<Buffer> {
    const serverKey = process.env.ENCRYPTION_KEY!;
    let clientKey = await this.context.secrets.get('encryptionKey');
  
    // Force reset if keys don't match
    if (clientKey && clientKey !== serverKey) {
      await this.context.secrets.delete('encryptionKey');
      clientKey = undefined;
    }
  
    if (!clientKey) {
      await this.context.secrets.store('encryptionKey', serverKey);
      return Buffer.from(serverKey, 'hex');
    }
    return Buffer.from(clientKey, 'hex');
  }
  

  /** Handle auth token lifecycle */
  private async ensureValidAuthToken(): Promise<void> {
    let token = await this.context.secrets.get('authToken');
    
    if (!token || this.isTokenExpired(token)) {
      token = await this.refreshAuthToken();
    }
  }

  /** Validate token expiration */
  private isTokenExpired(token: string): boolean {
    try {
      const decoded = jwt.decode(token) as { exp: number };
      return Date.now() >= decoded.exp * 1000;
    } catch {
      return true;
    }
  }

  /** Refresh auth token with user interaction */
  private async refreshAuthToken(): Promise<string> {
    // ADD: Skip in local mode
    if (process.env.AUTH_MODE === 'local') {
      return process.env.FIXED_TOKEN!;
    }

    const username = await vscode.window.showInputBox({
      prompt: 'Enter your username',
      ignoreFocusOut: true
    });
    
    const password = await vscode.window.showInputBox({
      prompt: 'Enter your password',
      password: true,
      ignoreFocusOut: true
    });
  
    if (!username || !password) {
      throw new Error('Authentication required');
    }
  
    await this.login(username, password);
    
    const token = await this.context.secrets.get('authToken');
    if (!token) {
      throw new Error('Authentication failed - no token received');
    }
  
    return token;
  }

  private async validateKeyConsistency() {
    const storedKey = await this.context.secrets.get('encryptionKey');
    const serverKey = process.env.ENCRYPTION_KEY!;
    
    if (storedKey !== serverKey) {
      await this.context.secrets.store('encryptionKey', serverKey);
    }
  }
}