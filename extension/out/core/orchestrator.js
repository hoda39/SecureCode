"use strict";
// src/core/orchestrator.ts
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
exports.Orchestrator = void 0;
const fs_1 = require("fs");
const path_1 = require("path");
const child_process_1 = require("child_process");
const chokidar_1 = __importDefault(require("chokidar"));
const fs_2 = require("fs");
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
class Orchestrator {
    sourceFile;
    aflPath;
    eclipserDllPath;
    baseDir;
    aflMasterBox;
    aflSlaveBox;
    eclipserBox;
    seedDir;
    syncDir;
    logStream;
    activeProcesses = [];
    syncInterval;
    constructor(sourceFile, aflPath, eclipserDllPath) {
        this.sourceFile = sourceFile;
        this.aflPath = aflPath;
        this.eclipserDllPath = eclipserDllPath;
        console.log('🚀 Initializing orchestrator');
        console.log('📄 Source file:', sourceFile);
        console.log('🔧 AFL Path:', aflPath);
        console.log('💠 Eclipser DLL:', eclipserDllPath);
        // Add validation
        if (!fs.existsSync(sourceFile)) {
            throw new Error(`Source file not found: ${sourceFile}`);
        }
        if (!fs.existsSync(path.join(aflPath, 'afl-fuzz'))) {
            throw new Error(`afl-fuzz not found in ${aflPath}`);
        }
        const sourceName = (0, path_1.parse)(this.sourceFile).name;
        this.baseDir = (0, path_1.resolve)(__dirname, // Current directory of this file (src/core)
        '../../../', // Navigate up to project root (SecureCodeAnalyzer)
        'src/analysis_tools', `${sourceName}_box_analysis`);
        // Remove existing directory if present
        if ((0, fs_1.existsSync)(this.baseDir)) {
            console.log(`[*] Removing existing directory: ${this.baseDir}`);
            (0, fs_1.rmSync)(this.baseDir, { recursive: true, force: true });
        }
        // Initialize directory paths
        this.aflMasterBox = (0, path_1.join)(this.baseDir, 'afl-master-box');
        this.aflSlaveBox = (0, path_1.join)(this.baseDir, 'afl-slave-box');
        this.eclipserBox = (0, path_1.join)(this.baseDir, 'eclipser-box');
        this.seedDir = (0, path_1.join)(this.baseDir, 'seeds');
        this.syncDir = (0, path_1.join)(this.baseDir, 'syncdir');
        // Create directory structure
        console.log(`[*] Creating directory structure in: ${this.baseDir}`);
        [
            this.aflMasterBox,
            this.aflSlaveBox,
            this.eclipserBox,
            this.seedDir,
            this.syncDir
        ].forEach(dir => (0, fs_1.mkdirSync)(dir, { recursive: true }));
        // Initialize seed file
        (0, fs_1.writeFileSync)((0, path_1.join)(this.seedDir, 'input_seed'), 'fuzz');
        console.log(`[*] Created seed file: ${(0, path_1.join)(this.seedDir, 'input_seed')}`);
        // Create log file
        this.logStream = (0, fs_1.createWriteStream)((0, path_1.join)(this.eclipserBox, 'eclipser_log.txt'));
        // Set core pattern
        console.log('[*] Setting core pattern...');
        (0, child_process_1.spawnSync)('sh', ['-c', 'echo core | sudo tee /proc/sys/kernel/core_pattern'], { stdio: 'inherit' });
    }
    async run(timeoutMs = 100_000) {
        try {
            console.log('\n=== Compilation Phase ===');
            await this.compileTargets();
            console.log('\n=== Fuzzing Phase ===');
            await this.startFuzzers(timeoutMs);
            console.log('\n=== Crash Detection ===');
            return await this.waitForCrashes(timeoutMs);
        }
        finally {
            this.cleanup();
        }
    }
    async compileTargets() {
        console.log("[*] Compiling ASAN binary for AFL++...");
        await this.compileAsanBinary();
        console.log("[*] Compiling non-ASAN binary for Eclipser...");
        await this.compileNoAsanBinary();
    }
    compileAsanBinary() {
        return new Promise((resolve, reject) => {
            const cFlags = ['-g', '-O0', '-fno-stack-protector', '-z', 'execstack'];
            const args = [...cFlags, '-fsanitize=address', '-o', 'test_asan.bin', this.sourceFile];
            const compiler = this.getCompiler();
            const proc = (0, child_process_1.spawn)((0, path_1.join)(this.aflPath, compiler), args, {
                cwd: this.aflMasterBox,
                stdio: 'inherit',
                env: { ...process.env, AFL_USE_ASAN: '1' }
            });
            proc.on('exit', code => {
                if (code === 0) {
                    (0, fs_1.copyFileSync)((0, path_1.join)(this.aflMasterBox, 'test_asan.bin'), (0, path_1.join)(this.aflSlaveBox, 'test_asan.bin'));
                    resolve();
                }
                else {
                    reject(new Error(`ASAN build failed with code ${code}`));
                }
            });
        });
    }
    compileNoAsanBinary() {
        return new Promise((resolve, reject) => {
            const cFlags = ['-g', '-O0', '-fno-stack-protector', '-z', 'execstack'];
            const args = [...cFlags, '-o', 'test_noasan.bin', this.sourceFile];
            const compiler = this.getCompiler();
            const proc = (0, child_process_1.spawn)((0, path_1.join)(this.aflPath, compiler), args, { cwd: this.eclipserBox, stdio: 'inherit' });
            proc.on('exit', code => {
                code === 0 ? resolve() : reject(new Error(`Non-ASAN build failed with code ${code}`));
            });
        });
    }
    async startFuzzers(timeoutMs) {
        this.syncInterval = this.startSyncProcess();
        console.log("[*] Launching AFL++ master...");
        await this.launchProcess((0, path_1.join)(this.aflPath, 'afl-fuzz'), [
            '-i', this.seedDir,
            '-o', this.syncDir,
            '-M', 'afl-master',
            '-f', 'input',
            '--', './test_asan.bin', 'input'
        ], this.aflMasterBox, 'log.txt', timeoutMs);
        console.log("[*] Launching AFL++ slave...");
        await this.launchProcess((0, path_1.join)(this.aflPath, 'afl-fuzz'), [
            '-i', this.seedDir,
            '-o', this.syncDir,
            '-S', 'afl-slave',
            '-f', 'input',
            '--', './test_asan.bin', 'input'
        ], this.aflSlaveBox, 'log.txt', timeoutMs);
        console.log("[*] Launching Eclipser...");
        await this.launchProcess('dotnet', [
            this.eclipserDllPath,
            '-t', `${timeoutMs / 1000}`,
            '-v', '2',
            '-s', this.syncDir,
            '-o', (0, path_1.join)(this.syncDir, 'eclipser-output'),
            '-p', './test_noasan.bin',
            '--arg', 'input',
            '-f', 'input'
        ], this.eclipserBox, 'eclipser_log.txt', timeoutMs);
    }
    launchProcess(command, args, cwd, logFile, timeoutMs) {
        return new Promise(resolve => {
            const logStream = (0, fs_1.createWriteStream)((0, path_1.join)(cwd, logFile));
            const proc = (0, child_process_1.spawn)(command, args, {
                cwd,
                stdio: ['ignore', 'pipe', 'pipe'],
                detached: true
            });
            this.activeProcesses.push(proc);
            proc.stdout.pipe(logStream);
            proc.stderr.pipe(logStream);
            setTimeout(() => {
                try {
                    process.kill(-proc.pid, 'SIGKILL');
                }
                catch (err) {
                    if (err.code !== 'ESRCH')
                        throw err;
                }
            }, timeoutMs);
            resolve();
        });
    }
    startSyncProcess() {
        return setInterval(() => {
            const eclipserOut = (0, path_1.join)(this.syncDir, 'eclipser-output');
            if (!(0, fs_1.existsSync)(eclipserOut))
                return;
            (0, fs_1.readdirSync)(eclipserOut).forEach(file => {
                const src = (0, path_1.join)(eclipserOut, file);
                if ((0, fs_2.lstatSync)(src).isDirectory())
                    return;
                [(0, path_1.join)(this.syncDir, 'afl-master', 'queue'),
                    (0, path_1.join)(this.syncDir, 'afl-slave', 'queue')]
                    .forEach(queueDir => {
                    (0, fs_1.mkdirSync)(queueDir, { recursive: true });
                    const dest = (0, path_1.join)(queueDir, file);
                    if (!(0, fs_1.existsSync)(dest))
                        (0, fs_1.copyFileSync)(src, dest);
                });
            });
        }, 5000);
    }
    waitForCrashes(timeoutMs) {
        return new Promise((resolve, reject) => {
            const crashDir = (0, path_1.join)(this.syncDir, 'eclipser-output', 'crashes');
            const crashes = [];
            // Only start watching if the crash directory exists
            if (!(0, fs_1.existsSync)(crashDir)) {
                const timer = setTimeout(() => {
                    reject(new Error('No crashes detected within timeout'));
                }, timeoutMs);
                return;
            }
            const watcher = chokidar_1.default.watch(crashDir, {
                ignoreInitial: true,
                awaitWriteFinish: { stabilityThreshold: 2000 }
            });
            const timer = setTimeout(() => {
                watcher.close();
                crashes.length > 0
                    ? resolve(crashes)
                    : reject(new Error('No crashes detected within timeout'));
            }, timeoutMs);
            watcher
                .on('add', path => {
                crashes.push(path);
                clearTimeout(timer);
                watcher.close();
                resolve(crashes);
            })
                .on('error', err => reject(err));
        });
    }
    cleanup() {
        console.log('\n=== Cleanup Phase ===');
        clearInterval(this.syncInterval);
        this.activeProcesses.forEach(proc => {
            try {
                process.kill(-proc.pid, 'SIGKILL');
            }
            catch (err) {
                if (err.code !== 'ESRCH')
                    throw err;
            }
        });
        this.logStream.end();
        console.log('[*] Cleanup completed');
    }
    // Returns the full paths of all crash input files produced by Eclipser.
    getCrashInputs() {
        const crashDir = (0, path_1.join)(this.syncDir, 'eclipser-output', 'crashes');
        return (0, fs_1.existsSync)(crashDir)
            ? (0, fs_1.readdirSync)(crashDir).map(file => (0, path_1.join)(crashDir, file))
            : [];
    }
    // Returns the path to the ASAN-instrumented binary used by AFL++.
    getBinaryPath() {
        const path = (0, path_1.join)(this.aflMasterBox, 'test_asan.bin');
        if (!fs.existsSync(path)) {
            throw new Error(`ASAN binary not found at ${path}`);
        }
        return path;
    }
    getCompiler() {
        const ext = path.extname(this.sourceFile);
        return ext === '.c' ? 'afl-clang-fast' : 'afl-clang-fast++';
    }
}
exports.Orchestrator = Orchestrator;
//# sourceMappingURL=orchestrator.js.map