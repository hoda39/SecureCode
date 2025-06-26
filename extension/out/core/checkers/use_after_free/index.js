"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAfterFreeChecker = void 0;
const parser_1 = require("./parser");
const sarif_1 = require("./sarif");
exports.useAfterFreeChecker = {
    name: 'Use After Free',
    testInput: '', // No specific test input needed for UAF
    asanOptions: 'detect_stack_use_after_return=1,halt_on_error=0',
    parse: parser_1.parse,
    generateSarif: sarif_1.generateSarif
};
//# sourceMappingURL=index.js.map