import * as vscode from 'vscode';
import * as path from 'path';
import { AnalysisAPIClient } from '../api-client/index';
import dotenv from 'dotenv';

dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });

interface CustomDiagnostic extends vscode.Diagnostic {
  report: any;
}

// Add this type above your global variables
type PersistentStatusState = "initial" | "vulnerabilityCount";

// Global resources
let diagnosticCollection: vscode.DiagnosticCollection;
let hoverProviderDisposable: vscode.Disposable | undefined;
let statusBarTemporary: vscode.StatusBarItem | undefined;
let statusBarPersistent: vscode.StatusBarItem | undefined;
let vulnerabilityCounts = new Map<string, number>();  // URI -> count
let persistentStatusState = new Map<string, PersistentStatusState>(); // Track state per file
let vulnLineDecorationTypes: Record<string, vscode.TextEditorDecorationType>;
let fileDecorations = new Map<string, Record<string, vscode.Range[]>>();
let outputChannel: vscode.OutputChannel;
let apiClient: AnalysisAPIClient;
let currentAnalysisSession: {
  id: string;
  cancellationToken: vscode.CancellationTokenSource;
  poller?: NodeJS.Timeout;
} | undefined;

export async function activate(context: vscode.ExtensionContext) {
  // Create and register an output channel
  outputChannel = vscode.window.createOutputChannel("Secure Code Analyzer");
  context.subscriptions.push(outputChannel);

  // Create temporary status bar (left side)
  statusBarTemporary = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  context.subscriptions.push(statusBarTemporary);

  // Create persistent status bar (right side)
  statusBarPersistent = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarPersistent.command = 'secure-code-analyzer.restartAnalysis';
  statusBarPersistent.tooltip = 'Run CodeGuard Dynamic Analysis';
  context.subscriptions.push(statusBarPersistent);

  // Initialize both
  updateTemporaryStatus('Ready', false);
  updatePersistentStatus("initial"); // Changed to show "CodeGuard"

  vulnLineDecorationTypes = {
    'Critical': vscode.window.createTextEditorDecorationType({
      backgroundColor: 'rgba(139, 0, 0, 0.25)',  // Dark red with higher opacity
      isWholeLine: true,
      borderWidth: '0 0 0 4px',
      borderStyle: 'solid',
      borderColor: 'rgba(139, 0, 0, 0.9)',  // Darker red border
      after: {
        contentText: '  ⚠️ CRITICAL Risk',
        color: 'darkred',
        fontWeight: 'bold'
      }
    }),
    'High': vscode.window.createTextEditorDecorationType({
      backgroundColor: 'rgba(255, 0, 0, 0.15)',
      isWholeLine: true,
      borderWidth: '0 0 0 4px',
      borderStyle: 'solid',
      borderColor: 'rgba(255, 0, 0, 0.8)',
      after: {
        contentText: '  ⚠️ High Risk',
        color: 'red',
        fontWeight: 'normal'
      }
    }),
    'Medium': vscode.window.createTextEditorDecorationType({
      backgroundColor: 'rgba(255, 165, 0, 0.15)',
      isWholeLine: true,
      borderWidth: '0 0 0 4px',
      borderStyle: 'solid',
      borderColor: 'rgba(255, 165, 0, 0.8)',
      after: {
        contentText: '  ⚠️ Medium Risk',
        color: 'orange',
        fontWeight: 'normal'
      }
    }),
    'Low': vscode.window.createTextEditorDecorationType({
      backgroundColor: 'rgba(0, 191, 255, 0.15)',
      isWholeLine: true,
      borderWidth: '0 0 0 4px',
      borderStyle: 'solid',
      borderColor: 'rgba(0, 191, 255, 0.8)',
      after: {
        contentText: '  ⚠️ Low Risk',
        color: 'blue',
        fontWeight: 'normal'
      }
    }),
    'Info': vscode.window.createTextEditorDecorationType({
      backgroundColor: 'rgba(200, 200, 200, 0.15)',
      isWholeLine: true,
      borderWidth: '0 0 0 4px',
      borderStyle: 'solid',
      borderColor: 'rgba(150, 150, 150, 0.8)',
      after: {
        contentText: '  ℹ️ Info',
        color: 'gray',
        fontWeight: 'normal'
      }
    })
  };

  // Add to context subscriptions for disposal
  context.subscriptions.push({
    dispose: () => {
      if (vulnLineDecorationTypes) {
        Object.values(vulnLineDecorationTypes).forEach(decoration => 
          decoration.dispose()
        );
      }
    }
  });

   // Create diagnostic collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection('casr');
  context.subscriptions.push(diagnosticCollection);

  try {
    // Initialize secure API client
    apiClient = new AnalysisAPIClient({
      context,
      baseURL: 'https://localhost:3000/' //process.env.API_BASE_URL || 
    });
    
    // Dual-mode initialization
    if (process.env.AUTH_MODE === 'local') {
      // Local mode - simplified initialization
      await apiClient.initialize(false);
      outputChannel.appendLine('CodeGuard activated in Local Mode 🛡️');
      updateTemporaryStatus('CodeGuard activated in Local Mode 🛡️', false);
      setTimeout(() => updateTemporaryStatus('Ready', false), 3000);
    } else {
      // Multi-user mode - full initialization
      const firstRun = true; //!(await context.secrets.get('authToken'));
      const firstAdminCreated = await apiClient.initialize(firstRun);
      
      if (firstAdminCreated) {
        outputChannel.appendLine('CodeGuard activated in Multi-User Mode 🛡️');
        updateTemporaryStatus('CodeGuard activated in Multi-User Mode 🛡️', false);
        setTimeout(() => updateTemporaryStatus('Ready', false), 3000);
      }
      outputChannel.appendLine('Security components initialized 🔒');
    }

    // Register commands and handlers
    registerEventHandlers(context);
    registerCommands(context);

  } catch (error: any) {
    outputChannel.appendLine(`Initialization error: ${error.message}`);
    updateTemporaryStatus('Initialization failed', false);
  }
}

function registerCommands(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.commands.registerCommand('secure-code-analyzer.runDynamicAnalysis', 
      async () => await runDynamicAnalysis()
    ),
    vscode.commands.registerCommand('secure-code-analyzer.cancelDynamicAnalysis', 
      async () => await cancelDynamicAnalysis()
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('secure-code-analyzer.restartAnalysis', 
      async () => {
        await cancelDynamicAnalysis();
        await runDynamicAnalysis();
      }
    )
  );

  // Conditionally register user management commands
  if (process.env.AUTH_MODE !== 'local') {
    context.subscriptions.push(
      vscode.commands.registerCommand('secure-code-analyzer.registerUser', 
        async () => await registerNewUser()
      )
    );
  }
}

function registerEventHandlers(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      const file = editor?.document.fileName;
      const ext  = file && path.extname(file).toLowerCase();

      // Update persistent status bar when switching files
      if (file) {
        const state = persistentStatusState.get(file) || "initial";
        const count = vulnerabilityCounts.get(file) || 0;
        
        // Show appropriate status based on file state
        if (state === "initial") {
          updatePersistentStatus("initial");
        } else {
          updatePersistentStatus(count);
        }

        applyDecorationsForFile(file);
      }

      if (ext === '.c' || ext === '.cpp') {
        handleEditorChange(file!);
      }
    })
  );
}

async function registerNewUser() {
   // NEW: Prevent user creation in local mode
   if (process.env.AUTH_MODE === 'local') {
    updateTemporaryStatus('User registration is disabled in local mode', false);
    return;
  }

  try {
    const username = await vscode.window.showInputBox({
      prompt: 'Enter new username',
      ignoreFocusOut: true
    });
    
    const password = await vscode.window.showInputBox({
      prompt: 'Enter new password',
      password: true,
      ignoreFocusOut: true
    });

    const role = await vscode.window.showQuickPick(['user', 'admin'], {
      placeHolder: 'Select user role',
      ignoreFocusOut: true
    });

    if (username && password && role) {
      await apiClient.registerUser(username, password, role as 'admin' | 'user');
      updateTemporaryStatus(`User ${username} created successfully`, false);
    }
  } catch (error: any) {
    updateTemporaryStatus('Registration failed', false);
    outputChannel.appendLine(`Registration failed: ${error.message}`);
  }
}

async function runDynamicAnalysis() {
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    updateTemporaryStatus('No active editor - please open a C/C++ file first ⚠️', false);
    return;
  }

  const file = editor?.document.fileName;
  const ext  = file && path.extname(file).toLowerCase();
  if (ext !== '.c' && ext !== '.cpp') {
    updateTemporaryStatus('Open a C++ file first ⚠️', false);
    return;
  }

  // Reset state at start
  if (file) {
    vulnerabilityCounts.set(file, 0);
    persistentStatusState.set(file, "vulnerabilityCount"); // Mark as analyzed
    updatePersistentStatus(0); // Show 0 vulnerabilities during analysis

    // Clear existing decorations
    if (vulnLineDecorationTypes) {
      const editor = vscode.window.activeTextEditor;
      if (editor && editor.document.fileName === file) {
        Object.values(vulnLineDecorationTypes).forEach(decorationType => {
          editor.setDecorations(decorationType, []);
        });
      }
    }
    fileDecorations.delete(file);
  }

  cleanupAnalysisSession();
  const sourceFilePath = file;

  // Create both tokens/controllers
  const cancellationToken = new vscode.CancellationTokenSource();
  const abortController = new AbortController();
  
  currentAnalysisSession = {
    id: `pending_${Date.now()}`,
    cancellationToken: cancellationToken
  };

  try {
    outputChannel.appendLine(`Starting analysis on: ${sourceFilePath} 🔍`);
    updateTemporaryStatus(`Starting analysis on: ${sourceFilePath} 🔍`, true);

    // Link VS Code cancellation to axios abort
    cancellationToken.token.onCancellationRequested(() => {
      abortController.abort();
    });

    // Start analysis
    updateTemporaryStatus('Encrypting and submitting file...', true);
    // Store session reference locally
    const session = currentAnalysisSession;
    const analysisId = await apiClient.runDynamicAnalysis(
        sourceFilePath, 
        abortController.signal
    );

    // Check if session was cancelled during API call
    if (!currentAnalysisSession || session.id !== currentAnalysisSession.id) {
      return;
    }
    
    // Update with real analysis ID
    currentAnalysisSession.id = analysisId;
    outputChannel.appendLine(`Analysis session started: ${analysisId}`);
    updateTemporaryStatus(`Analysis session started: ${analysisId}`, true);

    // Start status polling
    currentAnalysisSession.poller = setInterval(() => {
      pollAnalysisStatus(analysisId, sourceFilePath, cancellationToken.token);
    }, 3000);

    // Handle cancellation
    cancellationToken.token.onCancellationRequested(() => {
      outputChannel.appendLine(`User cancelled analysis: ${analysisId}`);
      updateTemporaryStatus(`User cancelled analysis: ${analysisId}`, true);
      cleanupAnalysisSession();
      apiClient.cancelDynamicAnalysis(analysisId).catch(handleAnalysisError);
    });
  } catch (error: any) {
    if (error.name === 'CanceledError' || error.message.includes('aborted')) {
        outputChannel.appendLine('Analysis cancelled during operation');
        updateTemporaryStatus('Analysis cancelled', false);
        setTimeout(() => updateTemporaryStatus('Ready', false), 3000);
    } else {
        handleAnalysisError(error);
        updateTemporaryStatus('Analysis failed', false);
        setTimeout(() => updateTemporaryStatus('Ready', false), 3000);
    }
  }
}

async function pollAnalysisStatus(
  analysisId: string,
  sourceFilePath: string,
  token: vscode.CancellationToken
) {
  if (token.isCancellationRequested) return;

  try {
    const status = await apiClient.getAnalysisStatus(analysisId);
    outputChannel.appendLine(`Status for ${analysisId}: ${status.state}`);

    if(status?.state === 'initializing') {
      updateTemporaryStatus('Setting up fuzzing environment...', true);
    } else if(status?.state === 'fuzzing') {
      updateTemporaryStatus(`Fuzzing - ${status.crashes || 0} crashes found`, true);
    } else if(status?.state === 'analyzing') {
      updateTemporaryStatus(`Analyzing ${status.crashes || 0} crashes…`, true);
    } else if (status?.state === 'completed' || status?.state === 'failed') {
      clearInterval(currentAnalysisSession?.poller); 
      if (status?.state === 'completed') {
        await handleCompletedAnalysis(status, sourceFilePath);
      } 
      else if(status?.state === 'failed' && status.error?.includes('timed out')) {
        updateTemporaryStatus('Analysis timed out', false);
        setTimeout(() => updateTemporaryStatus('Ready', false), 3000);
      } else {
        handleFailedAnalysis(analysisId, status.error);
      }
      cleanupAnalysisSession();
    }
  } catch (error) {
    handlePollingError(error);
  }
}

async function handleCompletedAnalysis(status: any, sourceFilePath: string) {
  try {
    if (status.results?.length > 0) {
      await processCasrReports(status.results, sourceFilePath);

      // Update persistent count and state
      vulnerabilityCounts.set(sourceFilePath, status.results.length);
      persistentStatusState.set(sourceFilePath, "vulnerabilityCount");
      updatePersistentStatus(status.results.length);

      outputChannel.appendLine('Analysis completed with findings');
      updateTemporaryStatus(`${status.results.length} vulnerabilities found ⚠️`, false);

      setTimeout(() => updateTemporaryStatus('Ready', false), 5000);
    } else {
      // Update state and show 0 vulnerabilities
      vulnerabilityCounts.set(sourceFilePath, 0);
      persistentStatusState.set(sourceFilePath, "vulnerabilityCount");
      updatePersistentStatus(0);

      outputChannel.appendLine('Analysis completed successfully');
      updateTemporaryStatus('No vulnerabilities detected ✅', false);

      setTimeout(() => updateTemporaryStatus('Ready', false), 5000);
    }
  } catch (error: any) {
    outputChannel.appendLine(`Report error: ${error.stack}`);
    updateTemporaryStatus('Report generation failed', false);
    setTimeout(() => updateTemporaryStatus('Ready', false), 5000);
  }
}

function handleFailedAnalysis(analysisId: string, error?: string) {
  const message = error || 'Unknown error occurred';
  outputChannel.appendLine(`Analysis ${analysisId} failed: ${message}`);
  updateTemporaryStatus('Analysis failed', false);
  setTimeout(() => updateTemporaryStatus('Ready', false), 3000);
}

async function cancelDynamicAnalysis() {
  if (!currentAnalysisSession) {
    updateTemporaryStatus('No active analysis to cancel', false);
    return;
  }

  try {
    await apiClient.cancelDynamicAnalysis(currentAnalysisSession.id);
    outputChannel.appendLine(`User cancelled: ${currentAnalysisSession.id}`);
    updateTemporaryStatus('Analysis cancelled', false);
    setTimeout(() => updateTemporaryStatus('Ready', false), 3000);
  } catch (error: any) {
    outputChannel.appendLine(`Analysis Cancelation error: ${error.stack}`);
    updateTemporaryStatus('Analysis Cancelation error', false);
    setTimeout(() => updateTemporaryStatus('Ready', false), 3000);
  } finally {
    cleanupAnalysisSession();
  }
}

function cleanupAnalysisSession() {
  if (currentAnalysisSession) {
    clearInterval(currentAnalysisSession.poller);
    currentAnalysisSession.cancellationToken.dispose();
    outputChannel.appendLine(`Cleaned up resources for ${currentAnalysisSession.id}`);
    currentAnalysisSession = undefined;
  }
}

function handleEditorChange(newFilePath: string) {
  if (currentAnalysisSession) {
    updateTemporaryStatus('Analysis cancelled due to file change', false);
    cleanupAnalysisSession();
  }
}

function handleAnalysisError(error: any) {
  const message = error.response?.data?.error || error.message;
  outputChannel.appendLine(`Analysis error: ${error.stack}`);
  updateTemporaryStatus('File Analysis error', false);
  cleanupAnalysisSession();
}

function handlePollingError(error: any) {
  if (error.message.includes('404')) {
    outputChannel.appendLine('Analysis session expired');
    updateTemporaryStatus('Analysis session expired', false);
    cleanupAnalysisSession();
  } else {
    outputChannel.appendLine(`Polling error: ${error.stack}`);
    updateTemporaryStatus('Polling error', false);
  }
}

async function processCasrReports(reports: any[], sourceFilePath: string) {
  const diagnostics: CustomDiagnostic[] = [];
  const sourceFileName = path.basename(sourceFilePath);

  // Prepare decoration ranges grouped by severity
  const rangesBySeverity: Record<string, vscode.Range[]> = {
    Critical: [],
    High: [],
    Medium: [],
    Low: [],
    Info: []
  };

  // Process each CASR report
  for (const report of reports) {
    try {
      let crashLocation = null;

      // 1. First try to get location from CrashLine
      if (report.CrashLine) {
        const [file, lineStr] = report.CrashLine.split(':');
        if (file && file.includes(sourceFileName)) {
          crashLocation = {
            file,
            line: parseInt(lineStr)
          };
        }
      }

      // 2. Fallback to parsing Stacktrace
      if (!crashLocation && report.Stacktrace) {
        for (const frame of report.Stacktrace) {
          // Match file:line pattern in stack trace
          const match = frame.match(/([^:]+):(\d+)/);
          if (match && match[1].includes(sourceFileName)) {
            crashLocation = {
              file: match[1],
              line: parseInt(match[2])
            };
            break;
          }
        }
      }

      if (!crashLocation) continue;

      // Create diagnostic
      const line = crashLocation.line - 1;
      const lineLength = vscode.window.activeTextEditor?.document.lineAt(line).range.end.character ?? 0;
      const range = new vscode.Range(line, 0, line, lineLength); // Reasonable width
      
      // Use enhanced report fields
      const mapping = report.VulnerabilityMapping;
      const diagnostic: CustomDiagnostic = {
        range,
        message: `${report.cweId} (${mapping.cweDescription}) | ${mapping.abstractClass}`,
        severity: vscode.DiagnosticSeverity.Error,
        source: 'CodeGuard',
        code: report.cweId,
        report: report
      };
      diagnostics.push(diagnostic);

      const severity = mapping.severityLevel;
      if (severity) {
        // Normalize severity to capitalized format
        const normalizedSeverity = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
        
        if (vulnLineDecorationTypes[normalizedSeverity]) {
          rangesBySeverity[normalizedSeverity].push(range);
        } else {
          /* */
        }
      } else {
        /* */
      }
    } catch (error) {
      outputChannel.appendLine(`Error processing report: ${error}`);
    }
  }

  // Update diagnostics
  diagnosticCollection.clear();
  diagnosticCollection.set(vscode.Uri.file(sourceFilePath), diagnostics);

  // Store decorations for this file
  fileDecorations.set(sourceFilePath, rangesBySeverity);

  // Clean up previous hover provider
  if (hoverProviderDisposable) {
    hoverProviderDisposable.dispose();
    hoverProviderDisposable = undefined;
  }

  // Register new hover provider
  hoverProviderDisposable = vscode.languages.registerHoverProvider('cpp', {
    provideHover(document, position) {
      const line = position.line;
      const diagnostic = diagnostics.find(d => d.range.start.line === line);
      
      if (diagnostic) {
        const report = diagnostic.report;
        const mapping = report.VulnerabilityMapping;
        const severity = report.CrashSeverity || {};
        
        const markdown = new vscode.MarkdownString();
        
        // Header with CWE-like ID
        markdown.appendMarkdown(`### ${report.cweId} (${mapping.cweDescription})\n\n`);
        
        // Abstract and Severity
        markdown.appendMarkdown(`**Abstract**: ${mapping.abstractClass}\n\n`);
        markdown.appendMarkdown(`**Severity**: ${mapping.severityScore} (${mapping.severityLevel})\n\n`);
        
        // Vulnerability description
        markdown.appendMarkdown(`#### ${severity.Description || mapping.cweDescription}\n\n`);
        markdown.appendMarkdown(`${severity.Explanation || 'No additional explanation available'}\n\n`);
        
        // Show vulnerable code snippet
        if (report.Source) {
          markdown.appendMarkdown('**Vulnerable Code**:\n```cpp\n');
          report.Source.forEach((line: string) => markdown.appendMarkdown(`${line}\n`));
          markdown.appendMarkdown('```\n\n');
        }
        
        // Show vulnerable variable if available
        if (report.VulnerableVariable) {
          markdown.appendMarkdown(`**Vulnerable Variable**: \`${report.VulnerableVariable}\`\n\n`);
        }
        
        // Related resources
        markdown.appendMarkdown(`**More Details**: [View Documentation](https://cwe.mitre.org/data/definitions/${mapping.cweId}.html)\n\n`);
        
        if (report.Stacktrace?.length > 0) {
          markdown.appendMarkdown('**Call Stack**:\n');
          report.Stacktrace.slice(0, 5).forEach((frame: string) => {
            markdown.appendMarkdown(`- ${frame}\n`);
          });
        }
        return new vscode.Hover(markdown);
      }
      return null;
    }
  });

  // Apply decorations if this is the active file
  applyDecorationsForFile(sourceFilePath);

  // Show notification
  if (diagnostics.length > 0) {
    vscode.window.showInformationMessage(
      `Found ${diagnostics.length} vulnerabilities in ${sourceFileName}`
    );
  }
}

// In applyDecorationsForFile:
function applyDecorationsForFile(filePath: string) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    outputChannel.appendLine('No active text editor');
    return;
  }
  
  if (editor.document.fileName === filePath) {
    const decorations = fileDecorations.get(filePath);
    if (decorations) {
      Object.entries(vulnLineDecorationTypes).forEach(([severity, decorationType]) => {
        const ranges = decorations[severity] || [];
        editor.setDecorations(decorationType, ranges);
      });
    } else {
      /* */
    }
  } else {
    outputChannel.appendLine('Active editor does not match target file');
  }
}

function updateTemporaryStatus(message: string, spinning: boolean = false) {
  if (statusBarTemporary) {
    const spinner = spinning ? '$(sync~spin) ' : '';
    statusBarTemporary.text = `${spinner} 🛡️ CodeGuard: ${message}`;
    statusBarTemporary.show();
  }
}

// For persistent vulnerability count
function updatePersistentStatus(stateOrCount: "initial" | number) {
  if (!statusBarPersistent) return;

  if (stateOrCount === "initial") {
    statusBarPersistent.text = "CodeGuard";
    statusBarPersistent.tooltip = "Run CodeGuard Analysis";
    statusBarPersistent.backgroundColor = new vscode.ThemeColor('statusBarItem.background');
  } else {
    const count = stateOrCount;
    statusBarPersistent.text = `⚠️ ${count} Vulnerabilities Found`;
    statusBarPersistent.tooltip = "Re-run Analysis";
    
    // Color coding based on vulnerability count
    if (count > 10) {
      statusBarPersistent.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    } else if (count > 5) {
      statusBarPersistent.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else if (count > 0) {
      statusBarPersistent.backgroundColor = new vscode.ThemeColor('statusBarItem.infoBackground');
    } else {
      statusBarPersistent.backgroundColor = new vscode.ThemeColor('statusBarItem.background');
    }
  }
  statusBarPersistent.show();
}

export function deactivate() {
  cleanupAnalysisSession();
  // apiClient?.dispose();
  
  // Dispose status bar only on deactivation
  if (statusBarTemporary) {
    statusBarTemporary.dispose();
    statusBarTemporary = undefined;
  }

  if (statusBarPersistent) {
    statusBarPersistent.dispose();
    statusBarPersistent = undefined;
  }

  if (outputChannel) {
    outputChannel.appendLine('Secure Code Analyzer deactivated 🔒');
    outputChannel.dispose();
  }

  if (vulnLineDecorationTypes) {
    Object.values(vulnLineDecorationTypes).forEach(decorationType => {
      decorationType.dispose();
    });
  }
  fileDecorations.clear();
}