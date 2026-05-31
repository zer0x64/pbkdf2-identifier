import { execSync } from 'child_process';
import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';

const isDev = process.argv.includes('--dev');
const mode = isDev ? 'debug' : 'release';
console.log(`Building WASM module in ${mode} mode...`);

try {
  // 1. Build cargo target
  const cargoCmd = `cargo build --target wasm32-unknown-unknown --features wbindgen ${isDev ? '' : '--release'} -p pbkdf2-identifier`;
  console.log(`Executing: ${cargoCmd}`);
  execSync(cargoCmd, { stdio: 'inherit', cwd: '..' });

  // 2. Ensure target wasm exists
  const wasmPath = join('..', 'target', 'wasm32-unknown-unknown', mode, 'pbkdf2_identifier.wasm');
  if (!existsSync(wasmPath)) {
    throw new Error(`Compiled WASM file not found at ${wasmPath}`);
  }

  // 3. Ensure output directory exists
  const outDir = join('src', 'wasm');
  if (!existsSync(outDir)) {
    mkdirSync(outDir, { recursive: true });
  }

  // 4. Run wasm-bindgen
  // Note: we use wasm-bindgen command installed via cargo
  const wasmBindgenCmd = `wasm-bindgen ${wasmPath} --out-dir ${outDir} --target web`;
  console.log(`Executing: ${wasmBindgenCmd}`);
  execSync(wasmBindgenCmd, { stdio: 'inherit' });

  console.log('WASM compilation and bindgen output written successfully to src/wasm/');
} catch (error) {
  console.error('WASM Build failed:', error.message || error);
  process.exit(1);
}
