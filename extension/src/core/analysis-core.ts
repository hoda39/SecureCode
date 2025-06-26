import { runWithCasr } from './casr';
import * as path from 'path';

interface CancellationToken {
  isCancellationRequested: boolean;
  onCancel(callback: () => void): void;
}

export class AnalysisCore {
  // Unified analysis method for both single and multiple crashes
  async analyzeCrashes(
    executablePath: string,
    crashInputs: string | string[], // Accept single string or array
    options: {
      cancellationToken?: CancellationToken;
      onProgress?: (message: string) => void;
    }
  ) {
    // Normalize input to always be an array
    const inputs = Array.isArray(crashInputs) 
      ? crashInputs 
      : [crashInputs];
    
    const casrReports = [];
  
    try {
      for (const inputFile of inputs) {
        if (options.cancellationToken?.isCancellationRequested) {
          throw new Error('Analysis cancelled');
        }
  
        options.onProgress?.(`Analyzing input: ${path.basename(inputFile)}`);
        const casrReport = await runWithCasr(executablePath, inputFile, options.cancellationToken);

        // Add original input file path to report
        casrReport.inputFile = inputFile;
        
        casrReports.push(casrReport);
      }
  
      return casrReports;
    } finally {
      // Cleanup resources if needed
    }
  }
}