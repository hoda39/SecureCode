"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parse = parse;
function parse(output) {
    const regex = /==\d+==ERROR:\s+AddressSanitizer:\s+(stack-buffer-overflow)\s+on address\s+0x[0-9a-f]+\s+at pc\s+0x[0-9a-f]+\s+bp\s+0x[0-9a-f]+\s+sp\s+0x[0-9a-f]+[\s\S]*?#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^()\s]+):(\d+):(\d+)[\s\S]*?'[^']+'\s+\(line\s+(\d+)\)/;
    const match = output.match(regex);
    if (!match || match[1] != 'stack-buffer-overflow')
        return null;
    return {
        type: match[1],
        declarationFunction: match[2],
        declarationFile: match[3],
        declarationLine: parseInt(match[4], 10),
        declarationColumn: parseInt(match[5], 10),
        bufferDeclarationLine: parseInt(match[6], 10),
    };
}
//# sourceMappingURL=parser.js.map