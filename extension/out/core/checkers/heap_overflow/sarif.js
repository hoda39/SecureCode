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
    const encodedVulnUri = (0, sarif_1.encodeSarifUri)(location.declarationFile);
    // Get code snippets
    const bufferSnippet = (0, sarif_1.getCodeSnippet)(location.allocationLine, location.allocationFile);
    const vulnSnippet = (0, sarif_1.getCodeSnippet)(location.declarationLine, location.declarationFile);
    return {
        rule: {
            id: "CWE-122",
            name: "Heap-based Buffer Overflow",
            shortDescription: {
                text: "Detects Heap-based buffer overflow vulnerability where data is written outside the allocated buffer bounds."
            },
            helpUri: "https://cwe.mitre.org/data/definitions/122.html",
            fullDescription: {
                text: "A heap buffer overflow occurs when a program writes more data to a block of memory than allocated."
            }
        },
        result: {
            message: {
                text: `Heap Buffer Overflow vulnerability detected in ${path.basename(location.declarationFile)} in [${location.declarationFunction}] function`,
                markdown: `**[Critical] Heap Buffer Overflow detected in ${path.basename(location.declarationFile)}**`
            },
            ruleId: "CWE-122",
            level: "error",
            kind: "fail",
            baselineState: "new",
            locations: [{
                    physicalLocation: {
                        artifactLocation: { uri: encodedVulnUri },
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
                        file: location.allocationFile,
                        line: location.allocationLine,
                        message: "1. Identify heap buffer declaration 📌"
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: "2. Provide oversized input to trigger overflow 📝"
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: "3. Compile with ASan: -fsanitize=address -fstack-protector 🛠"
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: "4. Check ASan report for 'heap-buffer-overflow' warnings 📋"
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: "5. Fix the issue by using std::vector with bounds-checked access Or validate write operations match allocation size ✅"
                    }
                ])],
            stacks: [(0, sarif_1.createStackFrame)([
                    {
                        file: location.allocationFile,
                        line: location.allocationLine,
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