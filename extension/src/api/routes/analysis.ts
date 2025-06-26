import { Router } from 'express';
import { startDynamicAnalysis, getAnalysisStatus, cancelDynamicAnalysis  } from '../controllers/analysis';

const router = Router();

router.post('/analysis', startDynamicAnalysis);
router.get('/analysis/:id/status', getAnalysisStatus);
router.delete('/analysis/:id/cancel', cancelDynamicAnalysis );

export default router;