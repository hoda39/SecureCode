"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parse = parse;
function parse(output) {
    const regex = /==\d+==ERROR:\s+LeakSanitizer:\s+detected\s+(memory leaks)\s*[\s\S]*?#1\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^()\s]+):(\d+):(\d+)[\s\S]*?SUMMARY:\s+AddressSanitizer:\s+(\d+)\s+byte\(s\)\s+leaked/;
    const match = output.match(regex);
    if (!match || match[1] != 'memory leaks')
        return null;
    return {
        type: match[1].replace(/\s+/g, '-'),
        declarationFunction: match[2],
        declarationFile: match[3],
        declarationLine: parseInt(match[4], 10),
        declarationColumn: parseInt(match[5], 10),
        numberOfBytesLeaked: parseInt(match[6], 10)
    };
}
//# sourceMappingURL=parser.js.map