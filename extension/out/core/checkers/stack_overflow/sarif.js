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
    const encodedUri = (0, sarif_1.encodeSarifUri)(location.declarationFile);
    // Get code snippets
    const bufferSnippet = (0, sarif_1.getCodeSnippet)(location.bufferDeclarationLine, location.declarationFile);
    const vulnSnippet = (0, sarif_1.getCodeSnippet)(location.declarationLine, location.declarationFile);
    return {
        rule: {
            id: "CWE-121",
            name: "Stack-based Buffer Overflow",
            shortDescription: { text: "Detects stack buffer overflow vulnerability." },
            helpUri: "https://cwe.mitre.org/data/definitions/121.html",
            fullDescription: {
                text: "Stack buffer overflow occurs when a program writes beyond the bounds of a stack-allocated buffer."
            }
        },
        result: {
            message: {
                text: `Stack buffer overflow vulnerability detected in ${path.basename(location.declarationFile)} in [${location.declarationFunction}] function`,
                markdown: `**[Critical] Stack Buffer Overflow detected in ${path.basename(location.declarationFile)}**`
            },
            ruleId: "CWE-121",
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
                        line: location.bufferDeclarationLine,
                        message: "1. Identify stack buffer declaration 📌"
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: "2. Detect unsafe write operation ⚠️"
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: "3. Compile with ASan: -fsanitize=address -fstack-protector 🛠️"
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: "4. Check ASan report for 'stack-buffer-overflow' warnings 📋"
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: "5. Fix: Use bounds-checked functions like `strncpy` or validate input size ✅"
                    }
                ])],
            stacks: [(0, sarif_1.createStackFrame)([
                    {
                        file: location.declarationFile,
                        line: location.bufferDeclarationLine,
                        message: bufferSnippet
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: vulnSnippet
                    }
                ])]
        }
    };
}
//# sourceMappingURL=sarif.js.map