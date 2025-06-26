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
            id: "CWE-562",
            name: "Use After Return",
            shortDescription: { text: "Detects use of memory after it has been freed." },
            helpUri: "https://cwe.mitre.org/data/definitions/562.html",
            fullDescription: {
                text: "Use-after-return occurs when a program accesses stack memory through a pointer after the containing function has returned."
            }
        },
        result: {
            message: {
                text: `Use After Return vulnerability detected in ${path.basename(location.declarationFile)} in [${location.declarationFunction}] function`,
                markdown: `**[Critical] Use After Return detected in ${path.basename(location.declarationFile)}**`
            },
            ruleId: "CWE-562",
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
                        message: `1. Identify stack address return in function 📌`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `2. Detect invalid memory access after return ⚠️`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `3. Compile with ASan flags: -fsanitize=address -fsanitize-address-use-after-return=always 🛠️`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `4. Check ASan report for 'stack-use-after-return' warnings 📋`
                    },
                    {
                        file: location.declarationFile,
                        line: location.declarationLine,
                        message: `5. Fix: Avoid returning stack addresses or use dynamic allocation ✅`
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