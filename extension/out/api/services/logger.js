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
Object.defineProperty(exports, "__esModule", { value: true });
exports.securityLogMiddleware = exports.securityLogger = exports.SecurityLogger = void 0;
// src/api/services/logger.ts
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const luxon_1 = require("luxon");
const MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
const LOG_DIR = path.join(__dirname, '../../../logs');
class SecurityLogger {
    writeStream;
    currentDate;
    currentLogPath;
    constructor() {
        this.currentDate = luxon_1.DateTime.now().toFormat('yyyy-MM-dd');
        this.currentLogPath = this.getLogPath();
        this.ensureLogDirectory();
        this.createWriteStream();
        this.startLogCleanupScheduler();
    }
    getLogPath() {
        return path.join(LOG_DIR, `security-${this.currentDate}.csv`);
    }
    ensureLogDirectory() {
        if (!fs.existsSync(LOG_DIR)) {
            fs.mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 });
        }
    }
    createWriteStream() {
        const needsHeader = !fs.existsSync(this.currentLogPath);
        this.writeStream = fs.createWriteStream(this.currentLogPath, {
            flags: 'a',
            encoding: 'utf8',
            mode: 0o600
        });
        if (needsHeader) {
            this.writeStream.write('timestamp,method,path,userId,userRole,statusCode,responseTime,clientIP,userAgent,error,analysisId,requestSize,responseSize\n');
        }
    }
    checkForRotation() {
        const today = luxon_1.DateTime.now().toFormat('yyyy-MM-dd');
        if (today !== this.currentDate) {
            this.currentDate = today;
            this.currentLogPath = this.getLogPath();
            this.createWriteStream();
            return;
        }
        const stats = fs.statSync(this.currentLogPath);
        if (stats.size > MAX_LOG_SIZE) {
            this.currentLogPath = path.join(LOG_DIR, `security-${this.currentDate}-${Date.now()}.csv`);
            this.createWriteStream();
        }
    }
    startLogCleanupScheduler() {
        this.cleanupOldLogs();
        setInterval(() => this.cleanupOldLogs(), 86400000).unref();
    }
    cleanupOldLogs() {
        const retentionDays = 30;
        fs.readdir(LOG_DIR, (err, files) => {
            if (err)
                return;
            const now = Date.now();
            files.forEach(file => {
                if (file.startsWith('security-')) {
                    const filePath = path.join(LOG_DIR, file);
                    const { birthtime } = fs.statSync(filePath);
                    const ageDays = (now - birthtime.getTime()) / (1000 * 3600 * 24);
                    if (ageDays > retentionDays) {
                        fs.unlink(filePath, (err) => {
                            if (err)
                                console.error('Log cleanup failed:', err);
                        });
                    }
                }
            });
        });
    }
    log(entry) {
        this.checkForRotation();
        const csvLine = [
            `"${entry.timestamp}"`,
            `"${entry.method}"`,
            `"${entry.path}"`,
            `"${entry.userId || ''}"`,
            `"${entry.userRole || ''}"`,
            entry.statusCode,
            entry.responseTime,
            `"${entry.clientIP}"`,
            `"${entry.userAgent?.replace(/"/g, '""') || ''}"`,
            `"${entry.error?.replace(/"/g, '""') || ''}"`,
            `"${entry.analysisId || ''}"`,
            entry.requestSize,
            entry.responseSize
        ].join(',') + '\n';
        this.writeStream.write(csvLine, (err) => {
            if (err)
                console.error('Failed to write security log:', err);
        });
    }
    getRecentLogs() {
        return new Promise((resolve, reject) => {
            fs.readFile(this.currentLogPath, 'utf8', (err, data) => {
                if (err)
                    reject(err);
                else
                    resolve(data);
            });
        });
    }
}
exports.SecurityLogger = SecurityLogger;
exports.securityLogger = new SecurityLogger();
// Middleware integration
const securityLogMiddleware = () => {
    return async (req, res, next) => {
        const startTime = Date.now();
        const { method, path, headers, body, user } = req;
        const clientIP = req.ip ||
            req.headers['x-forwarded-for'] ||
            req.socket.remoteAddress;
        const oldSend = res.send;
        let responseSize = 0;
        res.send = function (body) {
            responseSize = Buffer.byteLength(JSON.stringify(body));
            return oldSend.call(res, body);
        };
        res.on('finish', () => {
            const logEntry = {
                timestamp: new Date().toISOString(),
                method: method,
                path: path,
                userId: user?.id,
                userRole: user?.role,
                statusCode: res.statusCode,
                responseTime: Date.now() - startTime,
                clientIP: clientIP?.toString() || 'unknown',
                userAgent: headers['user-agent'],
                error: res.locals.errorMessage,
                analysisId: body?.analysisId || req.params?.id,
                requestSize: req.socket.bytesRead,
                responseSize: responseSize
            };
            exports.securityLogger.log(logEntry);
        });
        res.on('error', (err) => {
            res.locals.errorMessage = err.message;
        });
        next();
    };
};
exports.securityLogMiddleware = securityLogMiddleware;
//# sourceMappingURL=logger.js.map