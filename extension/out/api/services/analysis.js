"use strict";
// src/api/services/analysis.ts
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
exports.AnalysisService = void 0;
const events_1 = require("events");
const crypto_1 = require("./crypto");
const token_1 = require("./token");
const analysis_core_1 = require("../../core/analysis-core");
const orchestrator_1 = require("../../core/orchestrator");
const compile_1 = require("../../core/compile");
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
const fs = __importStar(require("fs"));
dotenv_1.default.config({ path: path_1.default.resolve(__dirname, '../../../../.env') });
/**
 * Manages cancellation signaling.
 */
class CancellationToken {
    isCancelled = false;
    emitter = new events_1.EventEmitter();
    cancel() {
        if (!this.isCancelled) {
            this.isCancelled = true;
            this.emitter.emit('cancel');
        }
    }
    get isCancellationRequested() {
        return this.isCancelled;
    }
    onCancel(callback) {
        this.emitter.on('cancel', callback);
    }
    dispose() {
        this.emitter.removeAllListeners();
    }
}
class AnalysisService {
    encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    analysisCore = new analysis_core_1.AnalysisCore();
    activeAnalyses = new Map();
    static ANALYSIS_TIMEOUT = 300000; // 5 minutes
    async startAnalysis(encryptedContent, contentIV, encryptedPath, pathIV) {
        console.log('🔑 Starting analysis session');
        const analysisId = token_1.TokenService.generateAnalysisToken();
        const cancellationToken = new CancellationToken();
        let timeout;
        try {
            // Decrypt both content and path
            const decryptedContent = crypto_1.CryptoService.decrypt(encryptedContent, this.encryptionKey, contentIV);
            const decryptedPath = crypto_1.CryptoService.decrypt(encryptedPath, this.encryptionKey, pathIV);
            // Create secure temp structure
            let tempFilePath;
            if (process.env.NODE_ENV !== 'development') {
                tempFilePath = this.createSecureTempFile(decryptedPath, decryptedContent);
            }
            else {
                tempFilePath = decryptedPath;
            }
            console.log('🔐 Decrypted content length:', decryptedContent.length);
            console.log('📁 Temporary file path:', tempFilePath);
            // Initialize session with timeout handler
            const session = {
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
        }
        catch (error) {
            console.error('🔥 AnalysisService Error:', error);
            this.handleAnalysisError(analysisId, error);
            throw error;
        }
        finally {
            if (timeout)
                clearTimeout(timeout);
            // Schedule cleanup in 5 minutes
            setTimeout(() => this.cleanupAnalysis(analysisId), 300000);
        }
    }
    getAnalysisStatus(analysisId) {
        const session = this.activeAnalyses.get(analysisId);
        return session
            ? {
                id: analysisId,
                state: session.status,
                results: session.result,
                error: session.error,
                duration: Date.now() - session.startTime,
                crashes: session.crashes // NEW: Add crash count
            }
            : null;
    }
    cancelAnalysis(analysisId) {
        const session = this.activeAnalyses.get(analysisId);
        if (!session)
            return false;
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
    async executeAnalysis(analysisId, filePath, cancellationToken) {
        try {
            // Choose analysis mode based on environment
            if (process.env.ANALYSIS_MODE === 'FUZZING') {
                return await this.executeFuzzingAnalysis(analysisId, filePath, cancellationToken);
            }
            else {
                // Compile the source file first
                const outputPath = filePath.replace(/\.(c|cpp)$/, '');
                try {
                    await (0, compile_1.compileSourceFile)(filePath, outputPath);
                }
                catch (compileError) {
                    this.updateSession(analysisId, {
                        status: 'failed',
                        error: `Compilation failed: ${compileError}`
                    });
                    return;
                }
                // Create a default input file
                const inputFile = path_1.default.join(path_1.default.dirname(filePath), 'analysis_input');
                fs.writeFileSync(inputFile, 'A'.repeat(1000));
                // Use the analyzeCrashes method with single input
                const casrReports = await this.analysisCore.analyzeCrashes(outputPath, // executablePath
                inputFile, // single input file
                {
                    cancellationToken,
                    onProgress: (msg) => this.handleProgress(analysisId, msg)
                });
                // Clean up compiled binary and input file
                try {
                    await Promise.all([
                        fs.promises.unlink(outputPath),
                        fs.promises.unlink(inputFile)
                    ]);
                }
                catch (cleanupError) {
                    console.error('Cleanup error:', cleanupError);
                }
                this.updateSession(analysisId, {
                    status: 'completed',
                    result: casrReports
                });
            }
        }
        finally {
            // Cleanup temp file regardless of outcome
            if (process.env.NODE_ENV !== 'development') {
                try {
                    await fs.promises.unlink(filePath);
                }
                catch (error) {
                    console.error(`Temp file cleanup failed: ${error}`);
                }
            }
        }
    }
    // New method: Handle timeout scenario
    handleAnalysisTimeout(analysisId) {
        this.updateSession(analysisId, {
            status: 'failed',
            error: 'Analysis timed out after 5 minutes'
        });
        this.cleanupAnalysis(analysisId);
    }
    // New method: Central error handling
    handleAnalysisError(analysisId, error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        this.updateSession(analysisId, {
            status: 'failed',
            error: message
        });
    }
    createSecureTempFile(originalPath, content) {
        // Sanitize path
        const safePath = path_1.default.normalize(originalPath).replace(/^(\.\.(\/|\\|$))+/g, '');
        // Create temp directory structure
        const tempFullPath = path_1.default.join('/', safePath);
        const tempDir = path_1.default.dirname(safePath);
        // Create directories and write file
        fs.mkdirSync(tempDir, { recursive: true });
        fs.writeFileSync(tempFullPath, content);
        return tempFullPath;
    }
    cleanupAnalysis(analysisId) {
        const session = this.activeAnalyses.get(analysisId);
        if (session) {
            if (session.tempFilePath && process.env.NODE_ENV !== 'development') {
                // Remove the entire temp directory
                const tempDir = path_1.default.dirname(session.tempFilePath);
                try {
                    fs.rmSync(tempDir, { recursive: true, force: true });
                }
                catch (error) {
                    console.error(`Failed to remove temporary directory ${tempDir}:`, error);
                }
            }
            session.cancellationToken.dispose();
            this.activeAnalyses.delete(analysisId);
        }
    }
    updateSession(analysisId, update) {
        const session = this.activeAnalyses.get(analysisId);
        if (session) {
            this.activeAnalyses.set(analysisId, { ...session, ...update });
        }
    }
    handleProgress(analysisId, message) {
        const session = this.activeAnalyses.get(analysisId);
        if (session && session.status !== 'completed' && session.status !== 'failed' && session.status !== 'cancelled') {
            console.log(`[${analysisId}] ${message}`);
        }
    }
    // NEW: Fuzzing-based analysis flow
    async executeFuzzingAnalysis(analysisId, sourceFilePath, cancellationToken) {
        // Keep orchestrator in outer scope for cleanup
        const orchestrator = new orchestrator_1.Orchestrator(sourceFilePath, process.env.AFL_PATH, process.env.ECLIPSER_DLL_PATH);
        try {
            // Verify AFL installation
            if (!fs.existsSync(path_1.default.join(process.env.AFL_PATH, 'afl-fuzz'))) {
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
            const casrReports = await this.analysisCore.analyzeCrashes(BinaryPath, crashInputs, {
                cancellationToken,
                onProgress: (msg) => this.handleProgress(analysisId, msg)
            });
            this.updateSession(analysisId, {
                status: 'completed',
                result: casrReports,
                crashes: crashCount
            });
        }
        catch (error) {
            this.updateSession(analysisId, {
                status: 'failed',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
            throw error;
        }
        finally {
            // Ensure orchestrator cleans up its processes and dirs
            // orchestrator.cleanup();
        }
    }
    dispose() {
        this.activeAnalyses.forEach((_, id) => this.cleanupAnalysis(id));
    }
}
exports.AnalysisService = AnalysisService;
//# sourceMappingURL=analysis.js.map