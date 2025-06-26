import { Request, Response } from 'express';
import { AnalysisService } from '../services/analysis';
import { securityLogger } from '../services/logger';
import { AuthenticatedRequest } from '../middleware/auth';

const analysisService = new AnalysisService();

export const startDynamicAnalysis  = async (req: AuthenticatedRequest, res: Response) => {
  const startTime = Date.now();
  let analysisId: string | undefined;
  
  try {
    const { encryptedContent, contentIV, encryptedPath, pathIV } = req.body;
    const userId = req.user?.id || 'unknown';
    
    analysisId = await analysisService.startAnalysis(
      encryptedContent,
      contentIV,
      encryptedPath,
      pathIV
    );

    securityLogger.log({
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
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const statusCode = 500;

    securityLogger.log({
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

export const getAnalysisStatus = (req: AuthenticatedRequest, res: Response) => {
  const startTime = Date.now();
  const { id } = req.params;

  try {
    const status = analysisService.getAnalysisStatus(id);
    
    if (!status) {
      securityLogger.log({
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

    securityLogger.log({
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
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const statusCode = 500;

    securityLogger.log({
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

export const cancelDynamicAnalysis = (req: AuthenticatedRequest, res: Response) => {
  const startTime = Date.now();
  const { id } = req.params;

  try {
    const success = analysisService.cancelAnalysis(id);
    
    securityLogger.log({
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
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const statusCode = 500;

    securityLogger.log({
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