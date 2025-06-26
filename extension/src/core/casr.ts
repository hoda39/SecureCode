import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { promisify } from 'util';
import { mapVulnerability, extractVulnerableVariable } from './vulnerability-mapper';

const unlink = promisify(fs.unlink);
const writeFile = promisify(fs.writeFile);

interface CancellationToken {
  isCancellationRequested: boolean;
  onCancel(callback: () => void): void;
}

export async function runWithCasr(
  executablePath: string,
  inputFile: string,
  cancellationToken?: CancellationToken
): Promise<any> {
  const casrPath = process.env.CASR_PATH || 'casr-san';
  const reportDir = process.env.CASR_REPORT_DIR || path.dirname(executablePath);

  // Extract filename without extension from executablePath
  const baseName = path.basename(executablePath, path.extname(executablePath));
  const reportBaseName = `${baseName}_analysis`;

  const casrReportPath = path.join(reportDir, `${reportBaseName}_original.json`);
  const enhancedReportPath = path.join(reportDir, `${reportBaseName}.json`);

  return new Promise((resolve, reject) => {
    const casr = spawn(casrPath, [
      '-o', casrReportPath,
      '--', executablePath, inputFile
    ]);

    // if cancellation requested, kill the CASR child
    if (cancellationToken) {
      cancellationToken.onCancel(() => {
        casr.kill(); 
        reject(new Error('Analysis cancelled'));
      });
    }

    casr.on('close', async (code) => {
      if (code !== 0) {
        reject(new Error(`CASR failed with code ${code}`));
        return;
      }

      try {
        const data = await fs.promises.readFile(casrReportPath, 'utf8');
        const report = JSON.parse(data);
        
        // Enhance report with vulnerability mapping
        const vulnType = report.CrashSeverity?.ShortDescription || 'Unknown';
        report.VulnerabilityMapping = mapVulnerability(vulnType);
        
        // Add CWE-like ID
        report.cweId = `CWE-${report.VulnerabilityMapping.cweId}`;

        // Extract vulnerable variable
        report.VulnerableVariable = extractVulnerableVariable(report);
        
        // Save enhanced report to a new file
        await writeFile(enhancedReportPath, JSON.stringify(report, null, 2));

        // Keep report path for debugging
        report._casrReportPath = casrReportPath;
        report._enhancedReportPath = enhancedReportPath;
        resolve(report);
      } catch (err) {
        reject(err);
      } finally {
        unlink(casrReportPath).catch(() => {});
        unlink(enhancedReportPath).catch(() => {});
      }
    });
  });
}