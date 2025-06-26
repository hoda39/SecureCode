"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.heapOverflowChecker = void 0;
const parser_1 = require("./parser");
const sarif_1 = require("./sarif");
exports.heapOverflowChecker = {
    name: 'Heap Buffer Overflow',
    testInput: '',
    asanOptions: 'detect_stack_use_after_return=1',
    parse: parser_1.parse,
    generateSarif: sarif_1.generateSarif
};
//# sourceMappingURL=index.js.map