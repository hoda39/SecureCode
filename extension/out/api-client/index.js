"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AnalysisAPIClient = void 0;
const axios_1 = __importDefault(require("axios"));
const crypto_1 = require("../api/services/crypto");
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const jwt = __importStar(require("jsonwebtoken"));
const vscode = __importStar(require("vscode"));
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
const https_1 = __importDefault(require("https"));
dotenv_1.default.config({ path: path_1.default.resolve(__dirname, '../../../.env') });
class AnalysisAPIClient {
    api;
    encryptionKey;
    context;
    constructor(config) {
        this.context = config.context;
        this.api = axios_1.default.create({
            baseURL: 'https://localhost:3000/api', //config.baseURL || process.env.API_BASE_URL ||
            timeout: 300000,
            httpsAgent: new https_1.default.Agent({
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
    async initialize(firstRun = false) {
        this.encryptionKey = await this.getOrCreateEncryptionKey();
        // ADD: Local mode handling
        if (process.env.AUTH_MODE === 'local') {
            // Store fixed token for local mode
            await this.context.secrets.store('authToken', process.env.FIXED_TOKEN);
            return false; // No first admin created in local mode
        }
        let firstAdminCreated = false;
        if (firstRun) {
            firstAdminCreated = await this.handleFirstTimeSetup();
        }
        else {
            await this.ensureValidAuthToken();
        }
        return firstAdminCreated;
    }
    /** Encrypt and submit file for analysis */
    async runDynamicAnalysis(filePath, abortSignal) {
        const fileContent = await fs.promises.readFile(filePath, 'utf-8');
        // Encrypt file content and path separately
        const { iv: contentIV, encrypted: encryptedContent } = crypto_1.CryptoService.encrypt(fileContent, this.encryptionKey);
        const { iv: pathIV, encrypted: encryptedPath } = crypto_1.CryptoService.encrypt(filePath, this.encryptionKey);
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
    async getAnalysisStatus(analysisId) {
        const response = await this.api.get(`/analysis/${analysisId}/status`);
        return response.data;
    }
    /** Cancel ongoing analysis */
    async cancelDynamicAnalysis(analysisId) {
        await this.api.delete(`/analysis/${analysisId}/cancel`);
    }
    async register(username, password) {
        const response = await this.api.post('/auth/register', { username, password });
        if (response.status !== 201) {
            throw new Error('Registration failed');
        }
    }
    async login(username, password) {
        const response = await this.api.post('/auth/login', { username, password });
        const token = response.data.token;
        // Verify token structure before storing
        const decoded = jwt.decode(token);
        if (!decoded?.id || !decoded?.role) {
            throw new Error('Invalid token received from server');
        }
        await this.context.secrets.store('authToken', token);
    }
    async registerUser(username, password, role) {
        try {
            const response = await this.api.post('/auth/register', {
                username,
                password,
                role
            });
            if (response.status !== 201) {
                throw new Error('User registration failed');
            }
        }
        catch (error) {
            // Extract server error message from response
            const serverMessage = error.response?.data?.error || error.message;
            throw new Error(serverMessage);
        }
    }
    async listUsers() {
        const response = await this.api.get('/auth/users');
        return response.data;
    }
    isLocalMode() {
        return process.env.AUTH_MODE === 'local';
    }
    /* Axios request interceptor for auth headers */
    async authInterceptor(config) {
        const token = await this.context.secrets.get('authToken');
        if (token) {
            config.headers.set('Authorization', `Bearer ${token}`);
        }
        return config;
    }
    async handleFirstTimeSetup() {
        const registered = await this.promptFirstTimeRegistration();
        if (!registered) {
            throw new Error('Initial setup required - create an admin account');
        }
        return true;
    }
    async promptFirstTimeRegistration() {
        // ADD: Skip in local mode
        if (process.env.AUTH_MODE === 'local') {
            return false;
        }
        const choice = await vscode.window.showInformationMessage('Welcome to Secure Code Analyzer! Create your first admin account:', 'Create Account', 'Cancel');
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
    async getOrCreateEncryptionKey() {
        const serverKey = process.env.ENCRYPTION_KEY;
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
    async ensureValidAuthToken() {
        let token = await this.context.secrets.get('authToken');
        if (!token || this.isTokenExpired(token)) {
            token = await this.refreshAuthToken();
        }
    }
    /** Validate token expiration */
    isTokenExpired(token) {
        try {
            const decoded = jwt.decode(token);
            return Date.now() >= decoded.exp * 1000;
        }
        catch {
            return true;
        }
    }
    /** Refresh auth token with user interaction */
    async refreshAuthToken() {
        // ADD: Skip in local mode
        if (process.env.AUTH_MODE === 'local') {
            return process.env.FIXED_TOKEN;
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
    async validateKeyConsistency() {
        const storedKey = await this.context.secrets.get('encryptionKey');
        const serverKey = process.env.ENCRYPTION_KEY;
        if (storedKey !== serverKey) {
            await this.context.secrets.store('encryptionKey', serverKey);
        }
    }
}
exports.AnalysisAPIClient = AnalysisAPIClient;
//# sourceMappingURL=index.js.map