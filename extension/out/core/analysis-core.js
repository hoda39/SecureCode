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
exports.AnalysisCore = void 0;
const casr_1 = require("./casr");
const path = __importStar(require("path"));
class AnalysisCore {
    // Unified analysis method for both single and multiple crashes
    async analyzeCrashes(executablePath, crashInputs, // Accept single string or array
    options) {
        // Normalize input to always be an array
        const inputs = Array.isArray(crashInputs)
            ? crashInputs
            : [crashInputs];
        const casrReports = [];
        try {
            for (const inputFile of inputs) {
                if (options.cancellationToken?.isCancellationRequested) {
                    throw new Error('Analysis cancelled');
                }
                options.onProgress?.(`Analyzing input: ${path.basename(inputFile)}`);
                const casrReport = await (0, casr_1.runWithCasr)(executablePath, inputFile, options.cancellationToken);
                // Add original input file path to report
                casrReport.inputFile = inputFile;
                casrReports.push(casrReport);
            }
            return casrReports;
        }
        finally {
            // Cleanup resources if needed
        }
    }
}
exports.AnalysisCore = AnalysisCore;
//# sourceMappingURL=analysis-core.js.map