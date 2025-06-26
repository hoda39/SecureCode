"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.startAPIServer = startAPIServer;
const https_1 = __importDefault(require("https"));
const fs_1 = __importDefault(require("fs"));
const express_1 = __importDefault(require("express"));
const auth_1 = require("./middleware/auth");
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
const crypto_1 = __importDefault(require("crypto"));
const analysis_1 = __importDefault(require("./routes/analysis"));
const auth_2 = __importDefault(require("./routes/auth"));
const logger_1 = require("./services/logger");
dotenv_1.default.config({ path: path_1.default.resolve(process.cwd(), '.env') });

function startAPIServer() {
    validateEncryptionKey();
    const app = (0, express_1.default)();
    const port = 3000; // process.env.PORT ||
    // HTTPS Configuration
    const httpsOptions = {
        key: fs_1.default.readFileSync(process.env.SSL_KEY_PATH),
        cert: fs_1.default.readFileSync(process.env.SSL_CERT_PATH),
        passphrase: process.env.SSL_PASSPHRASE || ''
    };
    // Security Middleware
    app.use(express_1.default.json({ limit: '10mb' })); // Parse JSON with a 10MB limit
    app.use(express_1.default.urlencoded({ extended: true, limit: '10mb' })); // Parse URL-encoded data with a 10MB limit
    // Update middleware section
    app.use((0, logger_1.securityLogMiddleware)()); // Add security logging
    /*
    app.use((req, res, next) => {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
      next();
    });
    */
    // Public routes (no authentication required)
    app.use('/api', auth_2.default); // Mount auth routes first
    // Apply authentication to subsequent routes
    app.use('/api', auth_1.authenticate); // Now applies only to routes after this line
    // Authenticated routes
    app.use('/api', analysis_1.default);
    // Start the Express server
    /*
    const server = https.createServer(httpsOptions, app).listen(port, () => {
      console.log(`✅ Secure Analysis API running on https://localhost:${port}`);
    });
    */
    // Add to startAPIServer function
    const server = https_1.default.createServer(httpsOptions, app)
        .on('error', (err) => {
        console.error('⚠️ HTTPS Server Error:', err);
    })
        .listen(port, () => {
        console.log(`✅ Secure Analysis API running on https://localhost:${port}`);
    });
    // Add global error handlers
    process.on('uncaughtException', (err) => {
        console.error('‼️ Uncaught Exception:', err);
    });
    process.on('unhandledRejection', (reason, promise) => {
        console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
    });
    return {
        dispose: () => {
            server.close();
            console.log('Analysis API stopped');
        }
    };
}
function validateEncryptionKey() {
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    if (key.length !== 32) {
        throw new Error(`Invalid ENCRYPTION_KEY: must be 64-character hex string
     Current length: ${process.env.ENCRYPTION_KEY?.length || 0} characters
     Generated valid key: ${crypto_1.default.randomBytes(32).toString('hex')}`);
    }
}
// If the file is executed directly, start the API server unless running in test mode
if (process.env.NODE_ENV !== 'test' && require.main === module) {
    startAPIServer();
}
//# sourceMappingURL=server.js.map