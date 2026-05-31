import init, { identify_iterations, HashPrimitive } from '../wasm/pbkdf2_identifier.js';
import wasmUrl from '../wasm/pbkdf2_identifier_bg.wasm?url';

let wasmInitialized = false;

self.onmessage = async (e: MessageEvent) => {
  const { password, hash, salt, primitive, max } = e.data;

  try {
    if (!wasmInitialized) {
      console.log(`[Worker - Primitive ${primitive}] Initializing WASM...`);
      await init(wasmUrl);
      wasmInitialized = true;
      console.log(`[Worker - Primitive ${primitive}] WASM Initialized.`);
    }

    console.log(`[Worker - Primitive ${primitive}] Starting identify_iterations...`);
    const startTime = performance.now();
    const result = identify_iterations(password, hash, salt, primitive, max);
    const duration = performance.now() - startTime;

    console.log(`[Worker - Primitive ${primitive}] Finished in ${duration.toFixed(2)}ms. Result: ${result}`);

    self.postMessage({
      status: 'success',
      result, // number | undefined
      primitive,
      duration
    });
  } catch (error) {
    console.error(`[Worker - Primitive ${primitive}] Error:`, error);
    self.postMessage({
      status: 'error',
      error: error instanceof Error ? error.message : String(error),
      primitive
    });
  }
};
