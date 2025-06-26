"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.stackOverflowChecker = void 0;
const parser_1 = require("./parser");
const sarif_1 = require("./sarif");
exports.stackOverflowChecker = {
    name: 'Stack Buffer Overflow',
    testInput: 'A'.repeat(100),
    asanOptions: 'detect_stack_use_after_return=1',
    parse: parser_1.parse,
    generateSarif: sarif_1.generateSarif
};
//# sourceMappingURL=index.js.map