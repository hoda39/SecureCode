import https from 'https';
import fs from 'fs';
import express from 'express';
import { authenticate } from './middleware/auth';
import dotenv from 'dotenv';
import path from 'path';
import crypto from 'crypto';
import analysisRouter from './routes/analysis';
import authRouter from './routes/auth';
import { securityLogMiddleware, securityLogger } from './services/logger';

dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

export function startAPIServer() {
  validateEncryptionKey();

  const app = express();
  const port = 3000; // process.env.PORT ||

  // HTTPS Configuration
  const httpsOptions = {
    key: fs.readFileSync(process.env.SSL_KEY_PATH!),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH!),
    passphrase: process.env.SSL_PASSPHRASE || ''
  };

  // Security Middleware
  app.use(express.json({ limit: '10mb' })); // Parse JSON with a 10MB limit
  app.use(express.urlencoded({ extended: true, limit: '10mb' })); // Parse URL-encoded data with a 10MB limit

  // Update middleware section
  app.use(securityLogMiddleware()); // Add security logging
  
  /*
  app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
  });
  */

  // Public routes (no authentication required)
  app.use('/api', authRouter); // Mount auth routes first

  // Apply authentication to subsequent routes
  app.use('/api', authenticate); // Now applies only to routes after this line

  // Authenticated routes
  app.use('/api', analysisRouter);

  // Start the Express server
  /*
  const server = https.createServer(httpsOptions, app).listen(port, () => {
    console.log(`✅ Secure Analysis API running on https://localhost:${port}`);
  });
  */

  // Add to startAPIServer function
  const server = https.createServer(httpsOptions, app)
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
  const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  if (key.length !== 32) {
    throw new Error(`Invalid ENCRYPTION_KEY: must be 64-character hex string
     Current length: ${process.env.ENCRYPTION_KEY?.length || 0} characters
     Generated valid key: ${crypto.randomBytes(32).toString('hex')}`);
  }
}

// If the file is executed directly, start the API server unless running in test mode
if (process.env.NODE_ENV !== 'test' && require.main === module) {
  startAPIServer();
}
