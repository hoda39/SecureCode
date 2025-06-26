// src/core/orchestrator.ts

import { mkdirSync, copyFileSync, writeFileSync, existsSync, readdirSync, rmSync, createWriteStream } from 'fs';
import { join, resolve, parse } from 'path';
import { spawn, spawnSync, ChildProcess } from 'child_process';
import chokidar from 'chokidar';
import { lstatSync } from 'fs';
import * as path from 'path';
import * as fs from 'fs';

export class Orchestrator {
  private baseDir: string;
  private aflMasterBox: string;
  private aflSlaveBox: string;
  private eclipserBox: string;
  private seedDir: string;
  private syncDir: string;
  private logStream: ReturnType<typeof createWriteStream>;
  private activeProcesses: ChildProcess[] = [];
  private syncInterval!: NodeJS.Timeout;

  constructor(
    private sourceFile: string,
    private aflPath: string,
    private eclipserDllPath: string,
  ) {

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

    const sourceName = parse(this.sourceFile).name;
    this.baseDir = resolve(
      __dirname, // Current directory of this file (src/core)
      '../../../', // Navigate up to project root (SecureCodeAnalyzer)
      'src/analysis_tools', 
      `${sourceName}_box_analysis`
    );

    // Remove existing directory if present
    if (existsSync(this.baseDir)) {
      console.log(`[*] Removing existing directory: ${this.baseDir}`);
      rmSync(this.baseDir, { recursive: true, force: true });
    }

    // Initialize directory paths
    this.aflMasterBox = join(this.baseDir, 'afl-master-box');
    this.aflSlaveBox = join(this.baseDir, 'afl-slave-box');
    this.eclipserBox = join(this.baseDir, 'eclipser-box');
    this.seedDir = join(this.baseDir, 'seeds');
    this.syncDir = join(this.baseDir, 'syncdir');

    // Create directory structure
    console.log(`[*] Creating directory structure in: ${this.baseDir}`);
    [
      this.aflMasterBox,
      this.aflSlaveBox,
      this.eclipserBox,
      this.seedDir,
      this.syncDir
    ].forEach(dir => mkdirSync(dir, { recursive: true }));

    // Initialize seed file
    writeFileSync(join(this.seedDir, 'input_seed'), 'fuzz');
    console.log(`[*] Created seed file: ${join(this.seedDir, 'input_seed')}`);

    // Create log file
    this.logStream = createWriteStream(join(this.eclipserBox, 'eclipser_log.txt'));
    
    // Set core pattern
    console.log('[*] Setting core pattern...');
    spawnSync('sh', ['-c', 'echo core | sudo tee /proc/sys/kernel/core_pattern'], { stdio: 'inherit' });
  }

  public async run(timeoutMs = 100_000): Promise<string[]> {
    try {
      console.log('\n=== Compilation Phase ===');
      await this.compileTargets();

      console.log('\n=== Fuzzing Phase ===');
      await this.startFuzzers(timeoutMs);

      console.log('\n=== Crash Detection ===');
      return await this.waitForCrashes(timeoutMs);
    } finally {
      this.cleanup();
    }
  }

  private async compileTargets(): Promise<void> {
    console.log("[*] Compiling ASAN binary for AFL++...");
    await this.compileAsanBinary();
    
    console.log("[*] Compiling non-ASAN binary for Eclipser...");
    await this.compileNoAsanBinary();
  }

  private compileAsanBinary(): Promise<void> {
    return new Promise((resolve, reject) => {
      const cFlags = ['-g', '-O0', '-fno-stack-protector', '-z', 'execstack'];
      const args = [...cFlags, '-fsanitize=address', '-o', 'test_asan.bin', this.sourceFile];
      
      const compiler = this.getCompiler();
      const proc = spawn(
        join(this.aflPath, compiler),
        args,
        {
          cwd: this.aflMasterBox,
          stdio: 'inherit',
          env: { ...process.env, AFL_USE_ASAN: '1' }
        }
      );

      proc.on('exit', code => {
        if (code === 0) {
          copyFileSync(
            join(this.aflMasterBox, 'test_asan.bin'),
            join(this.aflSlaveBox, 'test_asan.bin')
          );
          resolve();
        } else {
          reject(new Error(`ASAN build failed with code ${code}`));
        }
      });
    });
  }

  private compileNoAsanBinary(): Promise<void> {
    return new Promise((resolve, reject) => {
      const cFlags = ['-g', '-O0', '-fno-stack-protector', '-z', 'execstack'];
      const args = [...cFlags, '-o', 'test_noasan.bin', this.sourceFile];

      const compiler = this.getCompiler();
      const proc = spawn(
        join(this.aflPath, compiler),
        args,
        { cwd: this.eclipserBox, stdio: 'inherit' }
      );

      proc.on('exit', code => {
        code === 0 ? resolve() : reject(new Error(`Non-ASAN build failed with code ${code}`));
      });
    });
  }

  private async startFuzzers(timeoutMs: number): Promise<void> {
    this.syncInterval = this.startSyncProcess();
    
    console.log("[*] Launching AFL++ master...");
    await this.launchProcess(
      join(this.aflPath, 'afl-fuzz'),
      [
        '-i', this.seedDir,
        '-o', this.syncDir,
        '-M', 'afl-master',
        '-f', 'input',
        '--', './test_asan.bin', 'input'
      ],
      this.aflMasterBox,
      'log.txt',
      timeoutMs
    );

    console.log("[*] Launching AFL++ slave...");
    await this.launchProcess(
      join(this.aflPath, 'afl-fuzz'),
      [
        '-i', this.seedDir,
        '-o', this.syncDir,
        '-S', 'afl-slave',
        '-f', 'input',
        '--', './test_asan.bin', 'input'
      ],
      this.aflSlaveBox,
      'log.txt',
      timeoutMs
    );

    console.log("[*] Launching Eclipser...");
    await this.launchProcess(
      'dotnet',
      [
        this.eclipserDllPath,
        '-t', `${timeoutMs/1000}`,
        '-v', '2',
        '-s', this.syncDir,
        '-o', join(this.syncDir, 'eclipser-output'),
        '-p', './test_noasan.bin',
        '--arg', 'input',
        '-f', 'input'
      ],
      this.eclipserBox,
      'eclipser_log.txt',
      timeoutMs
    );
  }

  private launchProcess(
    command: string,
    args: string[],
    cwd: string,
    logFile: string,
    timeoutMs: number
  ): Promise<void> {
    return new Promise(resolve => {
      const logStream = createWriteStream(join(cwd, logFile));
      const proc = spawn(command, args, {
        cwd,
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: true
      });

      this.activeProcesses.push(proc);
      
      proc.stdout.pipe(logStream);
      proc.stderr.pipe(logStream);

      setTimeout(() => {
        try {
          process.kill(-proc.pid!, 'SIGKILL');
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== 'ESRCH') throw err;
        }
      }, timeoutMs);

      resolve();
    });
  }

  private startSyncProcess(): NodeJS.Timeout {
    return setInterval(() => {
      const eclipserOut = join(this.syncDir, 'eclipser-output');
      if (!existsSync(eclipserOut)) return;

      readdirSync(eclipserOut).forEach(file => {
        const src = join(eclipserOut, file);
        if (lstatSync(src).isDirectory()) return;

        [join(this.syncDir, 'afl-master', 'queue'),
         join(this.syncDir, 'afl-slave', 'queue')]
          .forEach(queueDir => {
            mkdirSync(queueDir, { recursive: true });
            const dest = join(queueDir, file);
            if (!existsSync(dest)) copyFileSync(src, dest);
          });
      });
    }, 5000);
  }

  private waitForCrashes(timeoutMs: number): Promise<string[]> {
    return new Promise((resolve, reject) => {
        const crashDir = join(this.syncDir, 'eclipser-output', 'crashes');
        const crashes: string[] = [];
        
        // Only start watching if the crash directory exists
        if (!existsSync(crashDir)) {
            const timer = setTimeout(() => {
                reject(new Error('No crashes detected within timeout'));
            }, timeoutMs);
            return;
        }

        const watcher = chokidar.watch(crashDir, {
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

  private cleanup(): void {
    console.log('\n=== Cleanup Phase ===');
    clearInterval(this.syncInterval);
    this.activeProcesses.forEach(proc => {
      try {
        process.kill(-proc.pid!, 'SIGKILL');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ESRCH') throw err;
      }
    });
    this.logStream.end();
    console.log('[*] Cleanup completed');
  }

  // Returns the full paths of all crash input files produced by Eclipser.
  public getCrashInputs(): string[] {
    const crashDir = join(this.syncDir, 'eclipser-output', 'crashes');
    return existsSync(crashDir)
      ? readdirSync(crashDir).map(file => join(crashDir, file))
      : [];
  }

  // Returns the path to the ASAN-instrumented binary used by AFL++.
  public getBinaryPath(): string {
    const path = join(this.aflMasterBox, 'test_asan.bin');
    if (!fs.existsSync(path)) {
      throw new Error(`ASAN binary not found at ${path}`);
    }
    return path;
  }

  private getCompiler(): string {
    const ext = path.extname(this.sourceFile);
    return ext === '.c' ? 'afl-clang-fast' : 'afl-clang-fast++';
  }
  
}