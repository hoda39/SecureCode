"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cancelDynamicAnalysis = exports.getAnalysisStatus = exports.startDynamicAnalysis = void 0;
const analysis_1 = require("../services/analysis");
const logger_1 = require("../services/logger");
const analysisService = new analysis_1.AnalysisService();
const startDynamicAnalysis = async (req, res) => {
    const startTime = Date.now();
    let analysisId;
    try {
        const { encryptedContent, contentIV, encryptedPath, pathIV } = req.body;
        const userId = req.user?.id || 'unknown';
        analysisId = await analysisService.startAnalysis(encryptedContent, contentIV, encryptedPath, pathIV);
        logger_1.securityLogger.log({
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            userId: req.user?.id,
            userRole: req.user?.role,
            statusCode: 202,
            responseTime: Date.now() - startTime,
            clientIP: req.ip ||
                req.headers['x-forwarded-for']?.toString() ||
                req.socket.remoteAddress ||
                'unknown',
            userAgent: req.headers['user-agent'],
            analysisId,
            requestSize: req.socket.bytesRead,
            responseSize: 0
        });
        res.status(202).json({
            analysisId,
            statusUrl: `/api/analysis/${analysisId}/status`
        });
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        const statusCode = 500;
        logger_1.securityLogger.log({
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            userId: req.user?.id,
            userRole: req.user?.role,
            statusCode,
            responseTime: Date.now() - startTime,
            clientIP: req.ip ||
                req.headers['x-forwarded-for']?.toString() ||
                req.socket.remoteAddress ||
                'unknown',
            userAgent: req.headers['user-agent'],
            error: errorMessage,
            analysisId,
            requestSize: req.socket.bytesRead,
            responseSize: 0
        });
        res.status(statusCode).json({
            error: 'Failed to start analysis',
            details: errorMessage
        });
    }
};
exports.startDynamicAnalysis = startDynamicAnalysis;
const getAnalysisStatus = (req, res) => {
    const startTime = Date.now();
    const { id } = req.params;
    try {
        const status = analysisService.getAnalysisStatus(id);
        if (!status) {
            logger_1.securityLogger.log({
                timestamp: new Date().toISOString(),
                method: req.method,
                path: req.path,
                userId: req.user?.id,
                userRole: req.user?.role,
                statusCode: 404,
                responseTime: Date.now() - startTime,
                clientIP: req.ip ||
                    req.headers['x-forwarded-for']?.toString() ||
                    req.socket.remoteAddress ||
                    'unknown',
                userAgent: req.headers['user-agent'],
                error: 'Analysis not found',
                analysisId: id,
                requestSize: req.socket.bytesRead,
                responseSize: 0
            });
            res.status(404).json({ error: 'Analysis not found' });
            return;
        }
        logger_1.securityLogger.log({
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            userId: req.user?.id,
            userRole: req.user?.role,
            statusCode: 200,
            responseTime: Date.now() - startTime,
            clientIP: req.ip ||
                req.headers['x-forwarded-for']?.toString() ||
                req.socket.remoteAddress ||
                'unknown',
            userAgent: req.headers['user-agent'],
            analysisId: id,
            requestSize: req.socket.bytesRead,
            responseSize: 0
        });
        res.json(status);
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        const statusCode = 500;
        logger_1.securityLogger.log({
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            userId: req.user?.id,
            userRole: req.user?.role,
            statusCode,
            responseTime: Date.now() - startTime,
            clientIP: req.ip ||
                req.headers['x-forwarded-for']?.toString() ||
                req.socket.remoteAddress ||
                'unknown',
            userAgent: req.headers['user-agent'],
            error: errorMessage,
            analysisId: id,
            requestSize: req.socket.bytesRead,
            responseSize: 0
        });
        res.status(statusCode).json({ error: errorMessage });
    }
};
exports.getAnalysisStatus = getAnalysisStatus;
const cancelDynamicAnalysis = (req, res) => {
    const startTime = Date.now();
    const { id } = req.params;
    try {
        const success = analysisService.cancelAnalysis(id);
        logger_1.securityLogger.log({
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            userId: req.user?.id,
            userRole: req.user?.role,
            statusCode: 200,
            responseTime: Date.now() - startTime,
            clientIP: req.ip ||
                req.headers['x-forwarded-for']?.toString() ||
                req.socket.remoteAddress ||
                'unknown',
            userAgent: req.headers['user-agent'],
            analysisId: id,
            requestSize: req.socket.bytesRead,
            responseSize: 0
        });
        res.json({ success });
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        const statusCode = 500;
        logger_1.securityLogger.log({
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            userId: req.user?.id,
            userRole: req.user?.role,
            statusCode,
            responseTime: Date.now() - startTime,
            clientIP: req.ip ||
                req.headers['x-forwarded-for']?.toString() ||
                req.socket.remoteAddress ||
                'unknown',
            userAgent: req.headers['user-agent'],
            error: errorMessage,
            analysisId: id,
            requestSize: req.socket.bytesRead,
            responseSize: 0
        });
        res.status(statusCode).json({
            error: 'Failed to cancel analysis',
            details: errorMessage
        });
    }
};
exports.cancelDynamicAnalysis = cancelDynamicAnalysis;
//# sourceMappingURL=analysis.js.map