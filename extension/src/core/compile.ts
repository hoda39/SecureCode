import { exec } from 'child_process';
import * as path from 'path';

export async function compileSourceFile(
  sourceFilePath: string, 
  outputPath: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    const ext = path.extname(sourceFilePath);
    const compiler = ext === '.c' ? 'clang' : 'clang++';
    const command = `${compiler} -fsanitize=address -fno-omit-frame-pointer -g "${sourceFilePath}" -o "${outputPath}"`;
    
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(`Compilation failed: ${error.message}`);
        return;
      }
      
      if (stderr) {
        console.warn(`Compiler warnings: ${stderr}`);
      }
      
      resolve();
    });
  });
}