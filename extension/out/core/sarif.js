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
exports.createBaseSarifReport = createBaseSarifReport;
exports.mergeSarifData = mergeSarifData;
exports.encodeSarifUri = encodeSarifUri;
exports.getCodeSnippet = getCodeSnippet;
exports.createCodeFlow = createCodeFlow;
exports.createStackFrame = createStackFrame;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/**
 * Creates a base SARIF report structure.
 */
function createBaseSarifReport() {
    return {
        $schema: "http://json.schemastore.org/sarif-2.1.0",
        version: "2.1.0",
        runs: [{
                tool: {
                    driver: {
                        name: "Secure Code Analyzer",
                        informationUri: "https://your-extension-docs.com",
                        rules: []
                    }
                },
                results: []
            }]
    };
}
/**
 * Merges SARIF data from different checkers into a single report.
 */
function mergeSarifData(baseReport, checkerData) {
    checkerData.forEach(data => {
        // Merge rules
        if (data.rule) {
            baseReport.runs[0].tool.driver.rules.push(data.rule);
        }
        // Merge results with full details
        if (data.result) {
            baseReport.runs[0].results.push({
                ...data.result,
                codeFlows: data.codeFlows || [],
                stacks: data.stacks || [],
                relatedLocations: data.relatedLocations || []
            });
        }
    });
}
/**
 * Encodes a file path as a file URI.
 * This implementation uses Node's path.resolve and constructs the URI manually.
 */
function encodeSarifUri(filePath) {
    const absolutePath = path.resolve(filePath).replace(/\\/g, '/');
    const encodedPath = absolutePath.replace(/#/g, '%23');
    // For Unix-like paths (starting with "/"), use "file://"
    // For Windows paths (e.g., "C:/"), use "file:///"
    return absolutePath.startsWith('/')
        ? `file://${encodedPath}`
        : `file:///${encodedPath}`;
}
/**
 * Retrieves a code snippet from a file given a line number.
 * Uses process.cwd() as the workspace root.
 */
function getCodeSnippet(lineNumber, filePath) {
    const fullPath = path.resolve(filePath);
    try {
        const document = fs.readFileSync(fullPath, 'utf-8');
        return document.split('\n')[lineNumber - 1]?.trim() || '';
    }
    catch (error) {
        return 'Unable to retrieve code snippet';
    }
}
/**
 * Creates a SARIF code flow from a list of locations.
 */
function createCodeFlow(locations) {
    return {
        threadFlows: [{
                locations: locations.map(loc => ({
                    location: {
                        physicalLocation: {
                            artifactLocation: { uri: encodeSarifUri(loc.file) },
                            region: { startLine: loc.line }
                        },
                        message: { text: loc.message }
                    }
                }))
            }]
    };
}
/**
 * Creates a SARIF stack frame from a list of frames.
 */
function createStackFrame(frames) {
    return {
        message: { text: "Vulnerability stack trace: " },
        frames: frames.map(frame => ({
            location: {
                physicalLocation: {
                    artifactLocation: { uri: encodeSarifUri(frame.file) },
                    region: {
                        startLine: frame.line,
                        startColumn: 1,
                        endLine: frame.line,
                        endColumn: 1000
                    }
                },
                message: { text: frame.message }
            }
        }))
    };
}
//# sourceMappingURL=sarif.js.map