// orchestrator-runner.ts

import { resolve } from 'path';
import { Orchestrator } from './orchestrator';

// Match timeout from Orchestrator.ts (100 seconds = 100,000 ms)
const DEFAULT_TIMEOUT_MS = 100_000; 

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 3) {
    console.log('Usage: ts-node orchestrator-runner.ts <AFL_PATH> <ECLIPSER_DLL> <TARGET_C> [TIMEOUT_MS]');
    console.log(`Default timeout: ${DEFAULT_TIMEOUT_MS}ms (${DEFAULT_TIMEOUT_MS/1000} seconds)`);
    process.exit(1);
  }

  const [aflPath, eclipserDll, targetC, timeoutArg] = args;
  
  try {
    const timeoutMs = timeoutArg ? parseInt(timeoutArg, 10) : DEFAULT_TIMEOUT_MS;
    
    const orchestrator = new Orchestrator(
      resolve(targetC),
      resolve(aflPath),
      resolve(eclipserDll)
    );
    
    const crashes = await orchestrator.run(timeoutMs);
    console.log('Crashes found:', crashes);
  } catch (err) {
    console.error('Fuzzing failed:', err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

main();

/*
ts-node orchestrator-runner.ts \
  ~/SecureCodeAnalyzer/Fuzzers/AFLplusplus/ \
  ~/SecureCodeAnalyzer/Fuzzers/Eclipser/build/Eclipser.dll \
  ~/SecureCodeAnalyzer/Fuzzers/Eclipser/examples/length.c
*/