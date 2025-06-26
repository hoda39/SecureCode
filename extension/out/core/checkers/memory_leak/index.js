"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.memoryLeakChecker = void 0;
const parser_1 = require("./parser");
const sarif_1 = require("./sarif");
exports.memoryLeakChecker = {
    name: 'Memory Leak',
    testInput: '', // No specific test input needed for UAF
    asanOptions: 'halt_on_error=0,detect_stack_use_after_return=1,detect_leaks=1',
    parse: parser_1.parse,
    generateSarif: sarif_1.generateSarif
};
//# sourceMappingURL=index.js.map