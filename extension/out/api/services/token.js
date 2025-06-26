"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenService = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const uuid_1 = require("uuid");
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
dotenv_1.default.config({ path: path_1.default.resolve(__dirname, '../../../../.env') });
class TokenService {
    static generateAuthToken(userId, role) {
        return jsonwebtoken_1.default.sign({
            id: userId,
            role: role,
            iat: Math.floor(Date.now() / 1000)
        }, process.env.JWT_SECRET, { expiresIn: '1h' });
    }
    static generateAnalysisToken() {
        return (0, uuid_1.v4)(); // Generate a new UUID (Universally Unique Identifier)
    }
}
exports.TokenService = TokenService;
//# sourceMappingURL=token.js.map