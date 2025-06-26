// src/api/services/analysis.ts

import { EventEmitter } from 'events';
import { CryptoService } from './crypto';
import { TokenService } from './token';
import { AnalysisCore } from '../../core/analysis-core';
import { Orchestrator } from '../../core/orchestrator';
import { compileSourceFile } from '../../core/compile';
import dotenv from 'dotenv';
import path from 'path';
import * as fs from 'fs';

dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });


/**
 * Represents an active analysis session.
 */
interface AnalysisSession {
  status: 'initializing' | 'fuzzing' | 'analyzing' | 'running' | 'completed' | 'failed' | 'cancelled';
  result?: any;
  error?: string;
  cancellationToken: CancellationToken;
  startTime: number;
  decryptedContent?: string;
  tempFilePath?: string;
  crashes?: number;  // NEW: Track crash count
}

/**
 * Manages cancellation signaling.
 */
class CancellationToken {
  private isCancelled = false;
  private emitter = new EventEmitter();

  cancel() {
    if (!this.isCancelled) {
      this.isCancelled = true;
      this.emitter.emit('cancel');
    }
  }

  get isCancellationRequested() {
    return this.isCancelled;
  }

  onCancel(callback: () => void) {
    this.emitter.on('cancel', callback);
  }

  dispose() {
    this.emitter.removeAllListeners();
  }
}

export class AnalysisService {
  private encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  private analysisCore = new AnalysisCore();
  private activeAnalyses = new Map<string, AnalysisSession>();
  private static ANALYSIS_TIMEOUT = 300000; // 5 minutes

  async startAnalysis(
    encryptedContent: string,
    contentIV: string,
    encryptedPath: string,
    pathIV: string
  ): Promise<string> {
    console.log('🔑 Starting analysis session');
    const analysisId = TokenService.generateAnalysisToken();
    const cancellationToken = new CancellationToken();
    let timeout!: NodeJS.Timeout;

    try {
      // Decrypt both content and path
      const decryptedContent = CryptoService.decrypt(
        encryptedContent,
        this.encryptionKey,
        contentIV
      );
      const decryptedPath = CryptoService.decrypt(
        encryptedPath,
        this.encryptionKey,
        pathIV
      );
      

      // Create secure temp structure
      let tempFilePath: string;
      if (process.env.NODE_ENV !== 'development') {
        tempFilePath = this.createSecureTempFile(
          decryptedPath,
          decryptedContent
        );
      } else {
        tempFilePath = decryptedPath;
      }

      console.log('🔐 Decrypted content length:', decryptedContent.length);
      console.log('📁 Temporary file path:', tempFilePath);

      // Initialize session with timeout handler
      const session: AnalysisSession = {
        status: 'running',
        decryptedContent,
        tempFilePath,
        cancellationToken,
        startTime: Date.now()
      };
      this.activeAnalyses.set(analysisId, session);

      // Set analysis timeout
      timeout = setTimeout(() => {
        this.handleAnalysisTimeout(analysisId);
      }, AnalysisService.ANALYSIS_TIMEOUT);

      // Execute core analysis
      await this.executeAnalysis(analysisId, tempFilePath, cancellationToken);

      return analysisId;
    } catch (error) {
      console.error('🔥 AnalysisService Error:', error);
      this.handleAnalysisError(analysisId, error);
      throw error;
    } finally {
      if (timeout) clearTimeout(timeout);
      // Schedule cleanup in 5 minutes
      setTimeout(() => this.cleanupAnalysis(analysisId), 300000);
    }
  }

  getAnalysisStatus(analysisId: string) {
    const session = this.activeAnalyses.get(analysisId);
    return session
      ? {
          id: analysisId,
          state: session.status,
          results: session.result,
          error: session.error,
          duration: Date.now() - session.startTime,
          crashes: session.crashes  // NEW: Add crash count
        }
      : null;
  }

  cancelAnalysis(analysisId: string): boolean {
    const session = this.activeAnalyses.get(analysisId);
    if (!session) return false;

    if (session.status === 'running' ||
        session.status === 'initializing' ||
        session.status === 'fuzzing' ||
        session.status === 'analyzing') {
      session.cancellationToken.cancel();
      this.updateSession(analysisId, { status: 'cancelled' });
      this.cleanupAnalysis(analysisId);
      return true;
    }

    return false;
  }

  // New method: Encapsulate analysis execution
  private async executeAnalysis(
    analysisId: string,
    filePath: string,
    cancellationToken: CancellationToken
  ) {
    try {
      // Choose analysis mode based on environment
      if (process.env.ANALYSIS_MODE === 'FUZZING') {
        return await this.executeFuzzingAnalysis(
          analysisId,
          filePath,
          cancellationToken
        );
      } else {
        // Compile the source file first
        const outputPath = filePath.replace(/\.(c|cpp)$/, '');
        
        try {
          await compileSourceFile(filePath, outputPath);
        } catch (compileError) {
          this.updateSession(analysisId, {
            status: 'failed',
            error: `Compilation failed: ${compileError}`
          });
          return;
        }
        
        // Create a default input file
        const inputFile = path.join(path.dirname(filePath), 'analysis_input');
        fs.writeFileSync(inputFile, 'A'.repeat(1000)); 
        
        // Use the analyzeCrashes method with single input
        const casrReports = await this.analysisCore.analyzeCrashes(
          outputPath,    // executablePath
          inputFile,     // single input file
          {
            cancellationToken,
            onProgress: (msg) => this.handleProgress(analysisId, msg)
          }
        );
        
        // Clean up compiled binary and input file
        try {
          await Promise.all([
            fs.promises.unlink(outputPath),
            fs.promises.unlink(inputFile)
          ]);
        } catch (cleanupError) {
          console.error('Cleanup error:', cleanupError);
        }
        
        this.updateSession(analysisId, {
          status: 'completed',
          result: casrReports
        });
      }
    } finally {
      // Cleanup temp file regardless of outcome
      if (process.env.NODE_ENV !== 'development') {
        try {
          await fs.promises.unlink(filePath);
        } catch (error) {
          console.error(`Temp file cleanup failed: ${error}`);
        }
      }
    }
  }

  // New method: Handle timeout scenario
  private handleAnalysisTimeout(analysisId: string) {
    this.updateSession(analysisId, {
      status: 'failed',
      error: 'Analysis timed out after 5 minutes'
    });
    this.cleanupAnalysis(analysisId);
  }

  // New method: Central error handling
  private handleAnalysisError(analysisId: string, error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    this.updateSession(analysisId, {
      status: 'failed',
      error: message
    });
  }

  private createSecureTempFile(
    originalPath: string,
    content: string
  ): string {
    // Sanitize path
    const safePath = path.normalize(originalPath).replace(/^(\.\.(\/|\\|$))+/g, '');

    // Create temp directory structure
    const tempFullPath = path.join('/', safePath);
    const tempDir = path.dirname(safePath);

    // Create directories and write file
    fs.mkdirSync(tempDir, { recursive: true });
    fs.writeFileSync(tempFullPath, content);

    return tempFullPath;
  }

  private cleanupAnalysis(analysisId: string) {
    const session = this.activeAnalyses.get(analysisId);
    if (session) {
      if (session.tempFilePath && process.env.NODE_ENV !== 'development') {
        // Remove the entire temp directory
        const tempDir = path.dirname(session.tempFilePath);
        try {
          fs.rmSync(tempDir, { recursive: true, force: true });
        } catch (error) {
          console.error(`Failed to remove temporary directory ${tempDir}:`, error);
        }
      }
      session.cancellationToken.dispose();
      this.activeAnalyses.delete(analysisId);
    }
  }

  private updateSession(analysisId: string, update: Partial<AnalysisSession>) {
    const session = this.activeAnalyses.get(analysisId);
    if (session) {
      this.activeAnalyses.set(analysisId, { ...session, ...update });
    }
  }

  private handleProgress(analysisId: string, message: string) {
    const session = this.activeAnalyses.get(analysisId);
    if (session && session.status !== 'completed' && session.status !== 'failed' && session.status !== 'cancelled') {
      console.log(`[${analysisId}] ${message}`);
    }
  }

  // NEW: Fuzzing-based analysis flow
  private async executeFuzzingAnalysis(
    analysisId: string,
    sourceFilePath: string,
    cancellationToken: CancellationToken
  ) {
    // Keep orchestrator in outer scope for cleanup
    const orchestrator = new Orchestrator(
      sourceFilePath,
      process.env.AFL_PATH!,
      process.env.ECLIPSER_DLL_PATH!
    );

    try {
      // Verify AFL installation
      if (!fs.existsSync(path.join(process.env.AFL_PATH!, 'afl-fuzz'))) {
        throw new Error(`afl-fuzz not found in ${process.env.AFL_PATH}`);
      }
      
      // INITIALIZING
      this.updateSession(analysisId, { status: 'initializing' });
      this.handleProgress(analysisId, "Initializing fuzzer...");

      // FUZZING
      this.updateSession(analysisId, { status: 'fuzzing' });
      this.handleProgress(analysisId, "Running fuzzing session...");
      await orchestrator.run(300000); // 5 minutes

      const crashInputs = orchestrator.getCrashInputs();
      const crashCount = crashInputs.length;
      const BinaryPath = orchestrator.getBinaryPath();

      if (crashCount === 0) {
        this.handleProgress(analysisId, "No crashes detected");
        this.updateSession(analysisId, {
          status: 'completed',
          result: [],
          crashes: crashCount
        });
        return;
      }

      // ANALYZING
      this.updateSession(analysisId, {
        status: 'analyzing',
        crashes: crashCount
      });
      this.handleProgress(analysisId, `Analyzing ${crashCount} crashes...`);

      // Use analyzeCrashes with multiple inputs
      const casrReports = await this.analysisCore.analyzeCrashes(
        BinaryPath,
        crashInputs,
        {
          cancellationToken,
          onProgress: (msg) => this.handleProgress(analysisId, msg)
        }
      );

      this.updateSession(analysisId, {
        status: 'completed',
        result: casrReports,
        crashes: crashCount
      });
    } catch (error) {
      this.updateSession(analysisId, {
        status: 'failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    } finally {
      // Ensure orchestrator cleans up its processes and dirs
      // orchestrator.cleanup();
    }
  }

  dispose() {
    this.activeAnalyses.forEach((_, id) => this.cleanupAnalysis(id));
  }
}
