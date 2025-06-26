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
exports.generateSarif = generateSarif;
const path = __importStar(require("path"));
const sarif_1 = require("../../sarif");
function generateSarif(location) {
    // Encode URI properly for SARIF compatibility
    const encodedUri = (0, sarif_1.encodeSarifUri)(location.declarationFile);
    // Get code snippets
    const allocationSnippet = (0, sarif_1.getCodeSnippet)(location.declarationLine, location.declarationFile);
    return {
        rule: {
            id: "CWE-401",
            name: "Memory Leak",
            shortDescription: { text: "Detects unreleased memory allocations." },
            helpUri: "https://cwe.mitre.org/data/definitions/401.html",
            fullDescription: {
                text: "Memory leak occurs when a program fails to release allocated memory, causing gradual memory consumption."
            }
        },
        result: {
            message: {
                text: `Memory leak vulnerability detected in ${path.basename(location.declarationFile)} in [ ${location.declarationFunction}] function`,
                markdown: `**[Critical] Memory leak detected in ${path.basename(location.declarationFile)}**`
            },
            ruleId: "CWE-401",
            level: "error",
            kind: "fail",
            locations: [{
                    physicalLocation: {
                        artifactLocation: { uri: encodedUri },
                        region: {
                            startLine: location.declarationLine,
                            startColumn: 1,
                            endLine: location.declarationLine,
                            endColumn: 1000
                        }
                    }
                }],
            codeFlows: [(0, sarif_1.createCodeFlow)([
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `1. Memory allocation point 📌`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `2. Missing corresponding deallocation ⚠️`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `3. Compile with ASan: -fsanitize=address 🛠`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `4. Check ASan report for 'detected memory leaks' 📋`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `5. Fix: Add missing free/delete or use smart pointers ✅`
                    }
                ])],
            stacks: [(0, sarif_1.createStackFrame)([
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `Memory allocated at line ${location.declarationLine}:\n${allocationSnippet}\n` + `Leaked ${location.numberOfBytesLeaked} bytes`
                    }
                ])]
        }
    };
}
//# sourceMappingURL=sarif.js.map