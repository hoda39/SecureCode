// src/api/services/logger.ts
import * as fs from 'fs';
import * as path from 'path';
import { Writable } from 'stream';
import { DateTime } from 'luxon';
import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';

const MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
const LOG_DIR = path.join(__dirname, '../../../logs');

interface SecurityLogEntry {
  timestamp: string;
  method: string;
  path: string;
  userId?: string;
  userRole?: string;
  statusCode: number;
  responseTime: number;
  clientIP: string;
  userAgent?: string;
  error?: string;
  analysisId?: string;
  requestSize: number;
  responseSize: number;
}

export class SecurityLogger {
  private writeStream!: Writable;
  private currentDate: string;
  private currentLogPath: string;

  constructor() {
    this.currentDate = DateTime.now().toFormat('yyyy-MM-dd');
    this.currentLogPath = this.getLogPath();
    this.ensureLogDirectory();
    this.createWriteStream();
    this.startLogCleanupScheduler();
  }

  private getLogPath(): string {
    return path.join(LOG_DIR, `security-${this.currentDate}.csv`);
  }

  private ensureLogDirectory(): void {
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 });
    }
  }

  private createWriteStream(): void {
    const needsHeader = !fs.existsSync(this.currentLogPath);
    this.writeStream = fs.createWriteStream(this.currentLogPath, {
      flags: 'a',
      encoding: 'utf8',
      mode: 0o600
    });

    if (needsHeader) {
      this.writeStream.write(
        'timestamp,method,path,userId,userRole,statusCode,responseTime,clientIP,userAgent,error,analysisId,requestSize,responseSize\n'
      );
    }
  }

  private checkForRotation(): void {
    const today = DateTime.now().toFormat('yyyy-MM-dd');
    
    if (today !== this.currentDate) {
      this.currentDate = today;
      this.currentLogPath = this.getLogPath();
      this.createWriteStream();
      return;
    }

    const stats = fs.statSync(this.currentLogPath);
    if (stats.size > MAX_LOG_SIZE) {
      this.currentLogPath = path.join(
        LOG_DIR,
        `security-${this.currentDate}-${Date.now()}.csv`
      );
      this.createWriteStream();
    }
  }

  private startLogCleanupScheduler(): void {
    this.cleanupOldLogs();
    setInterval(() => this.cleanupOldLogs(), 86400000).unref();
  }

  private cleanupOldLogs(): void {
    const retentionDays = 30;
    fs.readdir(LOG_DIR, (err, files) => {
      if (err) return;
      
      const now = Date.now();
      files.forEach(file => {
        if (file.startsWith('security-')) {
          const filePath = path.join(LOG_DIR, file);
          const { birthtime } = fs.statSync(filePath);
          const ageDays = (now - birthtime.getTime()) / (1000 * 3600 * 24);
          
          if (ageDays > retentionDays) {
            fs.unlink(filePath, (err) => {
              if (err) console.error('Log cleanup failed:', err);
            });
          }
        }
      });
    });
  }

  public log(entry: SecurityLogEntry): void {
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
      if (err) console.error('Failed to write security log:', err);
    });
  }

  public getRecentLogs(): Promise<string> {
    return new Promise((resolve, reject) => {
      fs.readFile(this.currentLogPath, 'utf8', (err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
}

export const securityLogger = new SecurityLogger();

// Middleware integration
export const securityLogMiddleware = () => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    const { method, path, headers, body, user } = req;
    const clientIP = req.ip || 
      req.headers['x-forwarded-for'] || 
      req.socket.remoteAddress;

    const oldSend = res.send;
    let responseSize = 0;

    res.send = function (body: any): Response {
      responseSize = Buffer.byteLength(JSON.stringify(body));
      return oldSend.call(res, body);
    };

    res.on('finish', () => {
      const logEntry: SecurityLogEntry = {
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

      securityLogger.log(logEntry);
    });

    res.on('error', (err) => {
      res.locals.errorMessage = err.message;
    });

    next();
  };
};