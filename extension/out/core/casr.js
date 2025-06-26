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
exports.runWithCasr = runWithCasr;
const child_process_1 = require("child_process");
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const util_1 = require("util");
const vulnerability_mapper_1 = require("./vulnerability-mapper");
const unlink = (0, util_1.promisify)(fs.unlink);
const writeFile = (0, util_1.promisify)(fs.writeFile);
async function runWithCasr(executablePath, inputFile, cancellationToken) {
    const casrPath = process.env.CASR_PATH || 'casr-san';
    const reportDir = process.env.CASR_REPORT_DIR || path.dirname(executablePath);
    // Extract filename without extension from executablePath
    const baseName = path.basename(executablePath, path.extname(executablePath));
    const reportBaseName = `${baseName}_analysis`;
    const casrReportPath = path.join(reportDir, `${reportBaseName}_original.json`);
    const enhancedReportPath = path.join(reportDir, `${reportBaseName}.json`);
    return new Promise((resolve, reject) => {
        const casr = (0, child_process_1.spawn)(casrPath, [
            '-o', casrReportPath,
            '--', executablePath, inputFile
        ]);
        // if cancellation requested, kill the CASR child
        if (cancellationToken) {
            cancellationToken.onCancel(() => {
                casr.kill();
                reject(new Error('Analysis cancelled'));
            });
        }
        casr.on('close', async (code) => {
            if (code !== 0) {
                reject(new Error(`CASR failed with code ${code}`));
                return;
            }
            try {
                const data = await fs.promises.readFile(casrReportPath, 'utf8');
                const report = JSON.parse(data);
                // Enhance report with vulnerability mapping
                const vulnType = report.CrashSeverity?.ShortDescription || 'Unknown';
                report.VulnerabilityMapping = (0, vulnerability_mapper_1.mapVulnerability)(vulnType);
                // Add CWE-like ID
                report.cweId = `CWE-${report.VulnerabilityMapping.cweId}`;
                // Extract vulnerable variable
                report.VulnerableVariable = (0, vulnerability_mapper_1.extractVulnerableVariable)(report);
                // Save enhanced report to a new file
                await writeFile(enhancedReportPath, JSON.stringify(report, null, 2));
                // Keep report path for debugging
                report._casrReportPath = casrReportPath;
                report._enhancedReportPath = enhancedReportPath;
                resolve(report);
            }
            catch (err) {
                reject(err);
            }
            finally {
                unlink(casrReportPath).catch(() => { });
                unlink(enhancedReportPath).catch(() => { });
            }
        });
    });
}
//# sourceMappingURL=casr.js.map