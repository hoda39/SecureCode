"use strict";
// src/api/middleware/auth.ts
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
exports.authenticate = void 0;
const jwt = __importStar(require("jsonwebtoken"));
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
dotenv_1.default.config({ path: path_1.default.resolve(__dirname, '../../../../.env') });
const authenticate = async (req, res, next) => {
    // Local single-user mode: validate against a fixed token
    if (process.env.AUTH_MODE === 'local') {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
            res.sendStatus(401);
            return;
        }
        const token = authHeader.split(' ')[1];
        if (token !== process.env.FIXED_TOKEN) {
            res.status(403).json({ error: 'Invalid access token' });
            return;
        }
        // Mock a user object for local mode
        req.user = {
            id: 'local-user',
            role: 'admin',
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600
        };
        return next();
    }
    // Multi-user mode: full JWT validation
    try {
        // Ensure secret is configured
        if (!process.env.JWT_SECRET) {
            throw new Error('JWT_SECRET environment variable not configured');
        }
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
            res.sendStatus(401);
            return;
        }
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256'],
            ignoreExpiration: false
        });
        // Validate payload structure
        if (typeof decoded.id !== 'string' || !['admin', 'user'].includes(decoded.role)) {
            throw new Error('Invalid token payload');
        }
        req.user = {
            id: decoded.id,
            role: decoded.role,
            iat: decoded.iat,
            exp: decoded.exp
        };
        next();
    }
    catch (error) {
        res.status(401).json({
            error: error instanceof Error ? error.message : 'Invalid token',
            code: 'INVALID_CREDENTIALS'
        });
    }
};
exports.authenticate = authenticate;
//# sourceMappingURL=auth.js.map