"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parse = parse;
function parse(output) {
    const regex = /==\d+==ERROR: AddressSanitizer: (\S+)[\s\S]*?#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^\s:()]+):(\d+)(?::(\d+))?[\s\S]*?freed by thread[\s\S]*?#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^\s:()]+):(\d+)(?::(\d+))?[\s\S]*?allocated by thread[\s\S]*?#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^\s:()]+):(\d+)(?::(\d+))?/;
    const match = output.match(regex);
    if (!match || match[1] != 'heap-use-after-free')
        return null;
    return {
        type: match[1],
        declarationFunction: match[2],
        declarationFile: match[3],
        declarationLine: parseInt(match[4], 10),
        declarationColumn: parseInt(match[5], 10),
        freeFunction: match[6],
        freeFile: match[7],
        freeLine: parseInt(match[8], 10),
        freeColumn: parseInt(match[9], 10),
        allocationFunction: match[10],
        allocationFile: match[11],
        allocationLine: parseInt(match[12], 10),
        allocationColumn: parseInt(match[13], 10)
    };
}
//# sourceMappingURL=parser.js.map