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
    const allocSnippet = (0, sarif_1.getCodeSnippet)(location.allocationLine, location.allocationFile);
    const freeSnippet = (0, sarif_1.getCodeSnippet)(location.freeLine, location.freeFile);
    const useSnippet = (0, sarif_1.getCodeSnippet)(location.declarationLine, location.declarationFile);
    return {
        rule: {
            id: "CWE-415",
            name: "Double Free",
            shortDescription: { text: "Detects duplicate memory deallocation attempts." },
            helpUri: "https://cwe.mitre.org/data/definitions/415.html",
            fullDescription: {
                text: "Double Free occurs when a program attempts to free memory that has already been deallocated."
            }
        },
        result: {
            message: {
                text: `Double Free vulnerability detected in ${path.basename(location.declarationFile)} in [ ${location.declarationFunction} ] function`,
                markdown: `**[Critical] Double Free vulnerability detected in ${path.basename(location.declarationFile)}**`
            },
            ruleId: "CWE-415",
            level: "error",
            kind: "fail",
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
                        message: `1. Trace memory allocation origin in ${location.allocationFunction}() 🔎`
                    },
                    {
                        file: location.freeFile,
                        line: location.freeLine,
                        message: `2. First valid free at line ${location.freeLine} (${path.basename(location.freeFile)}) ✅`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `3. Duplicate free detected at line ${location.declarationLine} ⚠️`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `4. Verify with ASan: compile with -fsanitize=address 🛠️`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `5. Check ASan report for 'double-free' stack traces 📋`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `6. Fix: Use RAII patterns or track ownership with null checks ✅`
                    }
                ])],
            stacks: [(0, sarif_1.createStackFrame)([
                    {
                        file: location.allocationFile,
                        line: location.allocationLine,
                        message: allocSnippet
                    },
                    {
                        file: location.freeFile,
                        line: location.freeLine,
                        message: freeSnippet
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: useSnippet
                    }
                ])]
        }
    };
}
//# sourceMappingURL=sarif.js.map