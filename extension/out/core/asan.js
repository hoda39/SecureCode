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
exports.compileWithASan = compileWithASan;
exports.runWithASan = runWithASan;
const child_process_1 = require("child_process");
const path = __importStar(require("path"));
const fs_1 = require("fs");
async function compileWithASan(sourceFilePath, outputPath) {
    return new Promise((resolve, reject) => {
        const ext = path.extname(sourceFilePath);
        const compiler = ext === '.c' ? 'clang' : 'clang++';
        const command = `${compiler} -fsanitize=address -fno-omit-frame-pointer -g "${sourceFilePath}" -o "${outputPath}"`;
        (0, child_process_1.exec)(command, (error, stdout, stderr) => {
            if (error)
                reject(`Compilation failed: ${error.message}`);
            if (stderr)
                reject(`Compiler warnings: ${stderr}`);
            resolve();
        });
    });
}
async function runWithASan(executablePath, testInput, // Can be a literal test string or a path to an input file
asanOptions, token) {
    // Determine if `testInput` refers to an existing file on disk
    const isFileInput = testInput.includes(path.sep) && (0, fs_1.existsSync)(testInput);
    // If it's a file, ASan can read it via the @<filename> syntax;
    // otherwise pass it as a normal argument string.
    const inputArg = isFileInput ? `@"${testInput}"` : `"${testInput}"`;
    // Build the full command line
    const command = `ASAN_OPTIONS=${asanOptions} "${executablePath}" ${inputArg}`;
    return new Promise((resolve, reject) => {
        // Launch the process
        const child = (0, child_process_1.exec)(command, (error, stdout, stderr) => {
            if (error && token?.isCancellationRequested) {
                return reject(new Error('Operation cancelled'));
            }
            // ASan diagnostics always go to stderr
            resolve(stderr);
        });
        // If provided, wire up the cancellation token
        if (token) {
            token.onCancellationRequested(() => {
                child.kill();
                reject(new Error('Operation cancelled'));
            });
        }
    });
}
//# sourceMappingURL=asan.js.map