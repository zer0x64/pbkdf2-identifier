<script lang="ts">
  import { onMount } from 'svelte';
  import IdentifyWorker from './workers/identify.worker.ts?worker';
  import { HashPrimitive } from './wasm/pbkdf2_identifier';

  // Build-time debug flag gating using custom PBKDF2_DEBUG env var
  // @ts-ignore
  const showDebugTools = __PBKDF2_DEBUG__;

  // Constants
  const PRIMITIVES = [
    { id: HashPrimitive.HMACSHA1, name: 'HMAC-SHA1', details: 'SHA-1 (160-bit digest)' },
    { id: HashPrimitive.HMACSHA224, name: 'HMAC-SHA224', details: 'SHA-224 (224-bit digest)' },
    { id: HashPrimitive.HMACSHA256, name: 'HMAC-SHA256', details: 'SHA-256 (256-bit digest)' },
    { id: HashPrimitive.HMACSHA384, name: 'HMAC-SHA384', details: 'SHA-384 (384-bit digest)' },
    { id: HashPrimitive.HMACSHA512, name: 'HMAC-SHA512', details: 'SHA-512 (512-bit digest)' },
  ];

  const HASH_SIZES = {
    [HashPrimitive.HMACSHA1]: 20,
    [HashPrimitive.HMACSHA224]: 28,
    [HashPrimitive.HMACSHA256]: 32,
    [HashPrimitive.HMACSHA384]: 48,
    [HashPrimitive.HMACSHA512]: 64,
  };

  // Types
  interface WorkerStatus {
    id: HashPrimitive;
    name: string;
    status: 'idle' | 'running' | 'completed' | 'found' | 'error' | 'cancelled';
    elapsedTime: number; // ms
    result?: number;
    error?: string;
    worker: Worker | null;
  }

  // App State Runes
  let passwordInput = $state('secret-password');
  let passwordType = $state<'text' | 'hex'>('text');

  let saltInput = $state('application-salt');
  let saltType = $state<'text' | 'hex' | 'base64'>('text');

  let hashInput = $state('3f64c0b53958c4c14e3780a95b792cb051ef54e5227a1a150dca4cbf6745dd1a');
  let hashType = $state<'hex' | 'base64'>('hex');

  let maxIterationsInput = $state<number>(100000);
  let selectedPrimitiveOption = $state<string>('all'); // 'all' or primitive id string

  // Execution State Runes
  let isRunning = $state(false);
  let globalElapsedTime = $state(0);
  let resultFound = $state<{ primitive: string; iterations: number; duration: number } | null>(null);
  let identificationFinished = $state(false);
  let identificationFailed = $state(false);
  let validationError = $state<string | null>(null);

  // Workers Status Runes
  let workers = $state<WorkerStatus[]>([
    { id: HashPrimitive.HMACSHA1, name: 'HMAC-SHA1', status: 'idle', elapsedTime: 0, worker: null },
    { id: HashPrimitive.HMACSHA224, name: 'HMAC-SHA224', status: 'idle', elapsedTime: 0, worker: null },
    { id: HashPrimitive.HMACSHA256, name: 'HMAC-SHA256', status: 'idle', elapsedTime: 0, worker: null },
    { id: HashPrimitive.HMACSHA384, name: 'HMAC-SHA384', status: 'idle', elapsedTime: 0, worker: null },
    { id: HashPrimitive.HMACSHA512, name: 'HMAC-SHA512', status: 'idle', elapsedTime: 0, worker: null },
  ]);

  // Quick Test Vector Generator State Runes
  let testPassword = $state('my-secure-password');
  let testSalt = $state('salt-bytes');
  let testIterations = $state(15000);
  let testPrimitive = $state(HashPrimitive.HMACSHA256);
  let generatingTest = $state(false);

  // Time tracking
  let globalStart = 0;
  let timerInterval: any = null;

  // Cleanup on destroy
  onMount(() => {
    return () => {
      terminateAllWorkers();
    };
  });

  // Helper Functions
  function hexToBytes(hex: string): Uint8Array {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2 !== 0) {
      throw new Error('Hex string must have an even number of characters');
    }
    const len = clean.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  function base64ToBytes(b64: string): Uint8Array {
    const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
    const binary = atob(clean);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Parse fields
  function getParsedInputs(): { password: Uint8Array; salt: Uint8Array; hash: Uint8Array } {
    validationError = null;
    let password: Uint8Array;
    let salt: Uint8Array;
    let hash: Uint8Array;

    // 1. Password
    try {
      if (passwordType === 'hex') {
        password = hexToBytes(passwordInput);
      } else {
        password = stringToBytes(passwordInput);
      }
    } catch (e: any) {
      throw new Error(`Password Parsing Error: ${e.message}`);
    }

    // 2. Salt
    try {
      if (saltType === 'hex') {
        salt = hexToBytes(saltInput);
      } else if (saltType === 'base64') {
        salt = base64ToBytes(saltInput);
      } else {
        salt = stringToBytes(saltInput);
      }
    } catch (e: any) {
      throw new Error(`Salt Parsing Error: ${e.message}`);
    }

    // 3. Hash
    try {
      if (hashType === 'hex') {
        hash = hexToBytes(hashInput);
      } else {
        hash = base64ToBytes(hashInput);
      }
    } catch (e: any) {
      throw new Error(`Hash Parsing Error: ${e.message}`);
    }

    if (hash.length === 0) {
      throw new Error('Hash length cannot be 0');
    }

    return { password, salt, hash };
  }

  // Terminate All Workers
  function terminateAllWorkers() {
    workers.forEach(w => {
      if (w.worker) {
        w.worker.terminate();
        w.worker = null;
      }
      if (w.status === 'running') {
        w.status = 'cancelled';
      }
    });

    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }
    isRunning = false;
  }

  // Kill Switch
  function handleCancel() {
    terminateAllWorkers();
    identificationFinished = true;
    identificationFailed = true;
    validationError = 'Identification cancelled by user.';
  }

  // Start Identification
  function startIdentification() {
    try {
      terminateAllWorkers();
      validationError = null;
      resultFound = null;
      identificationFinished = false;
      identificationFailed = false;

      const { password, salt, hash } = getParsedInputs();
      const maxIter = maxIterationsInput > 0 ? maxIterationsInput : undefined;

      // Identify which primitives to test
      let primitivesToRun: HashPrimitive[] = [];
      if (selectedPrimitiveOption === 'all') {
        primitivesToRun = PRIMITIVES.map(p => p.id);
      } else {
        primitivesToRun = [parseInt(selectedPrimitiveOption, 10)];
      }

      // Reset worker UI status
      workers.forEach(w => {
        if (primitivesToRun.includes(w.id)) {
          w.status = 'running';
          w.elapsedTime = 0;
          w.result = undefined;
          w.error = undefined;
        } else {
          w.status = 'idle';
          w.elapsedTime = 0;
        }
      });

      isRunning = true;
      globalStart = performance.now();

      // Start Time Tracker
      timerInterval = setInterval(() => {
        const now = performance.now();
        globalElapsedTime = now - globalStart;
        workers.forEach(w => {
          if (w.status === 'running') {
            w.elapsedTime = now - globalStart;
          }
        });
      }, 30);

      // Launch Workers
      primitivesToRun.forEach(primId => {
        const worker = new IdentifyWorker();
        const workerStatus = workers.find(w => w.id === primId)!;
        workerStatus.worker = worker;

        worker.onmessage = (e: MessageEvent) => {
          const { status, result, primitive, duration, error } = e.data;

          if (status === 'success') {
            if (result !== undefined) {
              // Iterations Found!
              workerStatus.status = 'found';
              workerStatus.result = result;
              workerStatus.elapsedTime = duration;

              // Immediately terminate all other workers
              terminateAllWorkers();

              // Record global found state
              resultFound = {
                primitive: PRIMITIVES.find(p => p.id === primitive)!.name,
                iterations: result,
                duration: duration
              };
              identificationFinished = true;
            } else {
              // Finished checking, not found
              workerStatus.status = 'completed';
              workerStatus.elapsedTime = duration;
              if (workerStatus.worker) {
                workerStatus.worker.terminate();
                workerStatus.worker = null;
              }

              // Check if all active workers are done
              checkAllFinished();
            }
          } else {
            // Worker errored
            workerStatus.status = 'error';
            workerStatus.error = error;
            workerStatus.elapsedTime = duration || (performance.now() - globalStart);
            if (workerStatus.worker) {
              workerStatus.worker.terminate();
              workerStatus.worker = null;
            }

            checkAllFinished();
          }
        };

        // Post work payload
        worker.postMessage({
          password,
          salt,
          hash,
          primitive: primId,
          max: maxIter
        });
      });

    } catch (e: any) {
      validationError = e.message;
      isRunning = false;
      if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
      }
    }
  }

  function checkAllFinished() {
    const activeRunning = workers.filter(w => w.status === 'running');
    if (activeRunning.length === 0 && isRunning) {
      // All running workers finished, and no result was found
      terminateAllWorkers();
      identificationFinished = true;
      identificationFailed = true;
    }
  }

  // Generate Test Vectors using Web Crypto API
  async function handleGenerateTestVector() {
    generatingTest = true;
    try {
      const encoder = new TextEncoder();
      const passBytes = encoder.encode(testPassword);
      const saltBytes = encoder.encode(testSalt);

      // Import key material
      const baseKey = await window.crypto.subtle.importKey(
        'raw',
        passBytes,
        'PBKDF2',
        false,
        ['deriveBits']
      );

      // Map HashPrimitive to standard names for Web Crypto API
      let digestName = 'SHA-256';
      let targetName = 'HMAC-SHA256';
      switch (testPrimitive) {
        case HashPrimitive.HMACSHA1:
          digestName = 'SHA-1';
          targetName = 'HMAC-SHA1';
          break;
        case HashPrimitive.HMACSHA224:
          digestName = 'SHA-224';
          targetName = 'HMAC-SHA224';
          break;
        case HashPrimitive.HMACSHA256:
          digestName = 'SHA-256';
          targetName = 'HMAC-SHA256';
          break;
        case HashPrimitive.HMACSHA384:
          digestName = 'SHA-384';
          targetName = 'HMAC-SHA384';
          break;
        case HashPrimitive.HMACSHA512:
          digestName = 'SHA-512';
          targetName = 'HMAC-SHA512';
          break;
      }

      const bitLength = HASH_SIZES[testPrimitive] * 8;

      console.log(`Generating test vector: PBKDF2 with ${targetName}, ${testIterations} iterations...`);

      const derivedBits = await window.crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: saltBytes,
          iterations: testIterations,
          hash: digestName
        },
        baseKey,
        bitLength
      );

      const generatedHashHex = bytesToHex(new Uint8Array(derivedBits));

      // Fill GUI fields
      passwordInput = testPassword;
      passwordType = 'text';

      saltInput = testSalt;
      saltType = 'text';

      hashInput = generatedHashHex;
      hashType = 'hex';

      maxIterationsInput = Math.max(testIterations + 50000, 100000);
      selectedPrimitiveOption = 'all'; // Set to all to test search

      console.log(`Test vector generated successfully! Hash (hex): ${generatedHashHex}`);
    } catch (err: any) {
      console.error('Failed to generate Web Crypto test vector:', err);
      alert('Error generating test vector: ' + err.message);
    } finally {
      generatingTest = false;
    }
  }
</script>

<div class="dashboard-container">
  <!-- Header -->
  <header class="app-header">
    <div class="logo-area">
      <h1>PBKDF2 Parameter Identifier</h1>
    </div>
    <p class="subtitle">
      Simple tool to identify PBKDF2 parameters. Obscurity is only an illusion of security.
    </p>
  </header>

  <!-- Main Workspace Grid -->
  <div class="workspace-grid">
    <!-- Left Column: inputs & Controls -->
    <div class="card form-card">
      <div class="card-header">
        <span class="icon">⚡</span>
        <h2>Input Configuration</h2>
      </div>

      <div class="form-group">
        <label for="password">Password Key Material</label>
        <div class="input-container">
          <input
            id="password"
            type={passwordType === 'text' ? 'text' : 'password'}
            bind:value={passwordInput}
            disabled={isRunning}
            placeholder={passwordType === 'hex' ? 'e.g. 736563726574' : 'e.g. secret-password'}
          />
          <select bind:value={passwordType} disabled={isRunning} class="type-select">
            <option value="text">UTF-8</option>
            <option value="hex">Hex</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label for="salt">Salt Value</label>
        <div class="input-container">
          <input
            id="salt"
            type="text"
            bind:value={saltInput}
            disabled={isRunning}
            placeholder={saltType === 'hex' ? 'e.g. 73616c74' : saltType === 'base64' ? 'e.g. c2FsdA==' : 'e.g. salt-bytes'}
          />
          <select bind:value={saltType} disabled={isRunning} class="type-select">
            <option value="text">UTF-8</option>
            <option value="hex">Hex</option>
            <option value="base64">Base64</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label for="hash">Target PBKDF2 Hash Digest</label>
        <div class="input-container font-mono">
          <input
            id="hash"
            type="text"
            bind:value={hashInput}
            disabled={isRunning}
            placeholder="e.g. ab3c89f..."
          />
          <select bind:value={hashType} disabled={isRunning} class="type-select">
            <option value="hex">Hex</option>
            <option value="base64">Base64</option>
          </select>
        </div>
      </div>

      <div class="form-row-2">
        <div class="form-group">
          <label for="max-iterations">Max Iterations Limit</label>
          <input
            id="max-iterations"
            type="number"
            bind:value={maxIterationsInput}
            disabled={isRunning}
            min="10"
            max="100000000"
          />
        </div>

        <div class="form-group">
          <label for="primitive-select">Hash Algorithm</label>
          <select id="primitive-select" bind:value={selectedPrimitiveOption} disabled={isRunning} class="primary-select">
            <option value="all">All Primitives (Parallel Search)</option>
            {#each PRIMITIVES as prim}
              <option value={prim.id.toString()}>{prim.name}</option>
            {/each}
          </select>
        </div>
      </div>

      {#if validationError}
        <div class="validation-error">
          <span class="error-icon">⚠️</span>
          <p>{validationError}</p>
        </div>
      {/if}

      <!-- Control Buttons -->
      <div class="actions-area">
        {#if !isRunning}
          <button class="btn btn-primary btn-glow" onclick={startIdentification}>
            <span class="btn-icon">▶</span> Identify Iterations
          </button>
        {:else}
          <button class="btn btn-danger btn-pulse" onclick={handleCancel}>
            <span class="btn-icon">■</span> Cancel / Kill Workers
          </button>
        {/if}
      </div>
    </div>

    <!-- Right Column: Monitoring & Results -->
    <div class="right-column">
      <!-- Readme & About Card -->
      <div class="card readme-card">
        <div class="card-header">
          <span class="icon">📖</span>
          <h2>About PBKDF2 Identifier</h2>
        </div>
        <p class="readme-text">
          This tool is designed to identify the exact PBKDF2 parameters (the underlying hash algorithm and iteration count) used to generate a given hash digest.
        </p>
        <p class="readme-text">
          To successfully identify these parameters, you must provide a <strong>valid password/hash pair</strong> and the salt. The tool runs checks locally in your browser using parallel Web Workers.
        </p>
        <div class="readme-footer">
          <a href="https://github.com/zer0x64/pbkdf2-identifier" target="_blank" rel="noopener noreferrer" class="btn btn-secondary github-btn">
            <svg class="gh-icon" viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.11.82-.26.82-.577v-2.234c-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.43.372.82 1.102.82 2.222v3.293c0 .319.22.694.825.576C20.565 21.795 24 17.3 24 12c0-6.63-5.37-12-12-12z" />
            </svg>
            GitHub Repository
          </a>
        </div>
      </div>

      <!-- Test Vector Generator (Gated behind showDebugTools build flag) -->
      {#if showDebugTools}
        <div class="card generator-card">
          <div class="card-header">
            <span class="icon">🧪</span>
            <h2>Quick Test Vector Generator</h2>
          </div>
          <p class="description-text">
            Generate a valid PBKDF2 hash using your browser's Web Crypto API to immediately test the WASM module.
          </p>

          <div class="generator-controls">
            <div class="input-grid">
              <div>
                <label for="test-pass">Password</label>
                <input id="test-pass" type="text" bind:value={testPassword} disabled={isRunning} />
              </div>
              <div>
                <label for="test-salt">Salt</label>
                <input id="test-salt" type="text" bind:value={testSalt} disabled={isRunning} />
              </div>
              <div>
                <label for="test-iterations">Iterations</label>
                <input id="test-iterations" type="number" bind:value={testIterations} disabled={isRunning} />
              </div>
              <div>
                <label for="test-prim">Algorithm</label>
                <select id="test-prim" bind:value={testPrimitive} disabled={isRunning}>
                  {#each PRIMITIVES as prim}
                    <option value={prim.id}>{prim.name}</option>
                  {/each}
                </select>
              </div>
            </div>
            <button class="btn btn-secondary" onclick={handleGenerateTestVector} disabled={isRunning || generatingTest}>
              {#if generatingTest}
                Generating...
              {:else}
                Inject Test Vector
              {/if}
            </button>
          </div>
        </div>
      {/if}

      <!-- Realtime monitor and result card -->
      <div class="card monitor-card">
        <div class="card-header flex-between">
          <div class="flex-row">
            <span class="icon">📊</span>
            <h2>Execution & Workers Monitor</h2>
          </div>
          {#if isRunning}
            <div class="running-indicator">
              <div class="spinner-small"></div>
              <span>Searching...</span>
            </div>
          {/if}
        </div>

        {#if !isRunning && !identificationFinished}
          <div class="empty-state">
            <div class="empty-icon">🔍</div>
            <h3>Ready to Run</h3>
            <p>Configure the parameters and hit "Identify Iterations" to launch Web Workers.</p>
          </div>
        {:else}
          <div class="monitor-dashboard">
            <!-- Global time -->
            <div class="global-stats">
              <div class="stat-box">
                <span class="label">Total Elapsed Time</span>
                <span class="value font-mono">{(globalElapsedTime / 1000).toFixed(3)}s</span>
              </div>
              <div class="stat-box">
                <span class="label">Active Workers</span>
                <span class="value font-mono">
                  {workers.filter(w => w.status === 'running').length} / {workers.filter(w => w.status !== 'idle').length}
                </span>
              </div>
            </div>

            <!-- List of Worker threads -->
            <div class="worker-list">
              {#each workers.filter(w => w.status !== 'idle') as worker}
                <div class="worker-row status-{worker.status}">
                  <div class="worker-meta">
                    <span class="worker-name">{worker.name}</span>
                    <span class="worker-details">{PRIMITIVES.find(p => p.id === worker.id)?.details}</span>
                  </div>

                  <div class="worker-state-col">
                    <span class="status-badge badge-{worker.status}">
                      {worker.status.toUpperCase()}
                    </span>
                    <span class="worker-timer font-mono">{(worker.elapsedTime / 1000).toFixed(2)}s</span>
                  </div>
                </div>
              {/each}
            </div>

            <!-- Finished Results Panel -->
            {#if identificationFinished}
              <div class="results-panel">
                {#if resultFound}
                  <div class="result-success-box">
                    <div class="result-icon">✨</div>
                    <div class="result-text-area">
                      <h3>Parameters Identified!</h3>
                      <div class="result-grid">
                        <div class="res-item">
                          <span class="res-lbl">Algorithm:</span>
                          <span class="res-val highlight-blue">{resultFound.primitive}</span>
                        </div>
                        <div class="res-item">
                          <span class="res-lbl">Iterations:</span>
                          <span class="res-val highlight-green font-mono">{resultFound.iterations.toLocaleString()}</span>
                        </div>
                        <div class="res-item">
                          <span class="res-lbl">Identified In:</span>
                          <span class="res-val font-mono">{(resultFound.duration / 1000).toFixed(3)}s</span>
                        </div>
                      </div>
                    </div>
                  </div>
                {:else if identificationFailed}
                  <div class="result-fail-box">
                    <div class="result-icon">❌</div>
                    <div class="result-text-area">
                      <h3>Identification Ended</h3>
                      <p>Checked all selected algorithms up to {maxIterationsInput.toLocaleString()} iterations, but no matching parameters were found.</p>
                    </div>
                  </div>
                {/if}
              </div>
            {/if}
          </div>
        {/if}
      </div>
    </div>
  </div>
</div>

<style>
  :global(body) {
    background-color: #0b0c10;
    color: #c5c6c7;
    font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
    margin: 0;
    padding: 0;
  }

  .dashboard-container {
    width: 100%;
    max-width: 1200px;
    margin: 0 auto;
    padding: 40px 20px;
    box-sizing: border-box;
  }

  /* Typography */
  .app-header {
    text-align: center;
    margin-bottom: 40px;
  }

  .logo-area {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }

  .wasm-badge {
    background: linear-gradient(135deg, #61dafb, #aa3bff);
    color: #fff;
    font-weight: 800;
    font-size: 0.75rem;
    padding: 3px 8px;
    border-radius: 6px;
    letter-spacing: 1px;
    box-shadow: 0 0 15px rgba(170, 59, 255, 0.4);
  }

  h1 {
    font-size: 2.5rem;
    font-weight: 800;
    color: #ffffff;
    margin: 0;
    letter-spacing: -0.5px;
    background: linear-gradient(to right, #ffffff, #8b9bb4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  .subtitle {
    color: #8f9aa8;
    font-size: 1.1rem;
    max-width: 600px;
    margin: 0 auto;
    line-height: 1.5;
  }

  /* Grid layout */
  .workspace-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 30px;
  }

  @media (min-width: 900px) {
    .workspace-grid {
      grid-template-columns: 500px 1fr;
    }
  }

  .right-column {
    display: flex;
    flex-direction: column;
    gap: 30px;
  }

  /* Cards */
  .card {
    background: rgba(21, 23, 30, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 16px;
    padding: 24px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    backdrop-filter: blur(12px);
    transition: transform 0.2s ease, border-color 0.2s ease;
  }

  .card:hover {
    border-color: rgba(170, 59, 255, 0.25);
  }

  .card-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 20px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    padding-bottom: 12px;
  }

  .card-header h2 {
    font-size: 1.25rem;
    font-weight: 700;
    color: #ffffff;
    margin: 0;
  }

  .card-header .icon {
    font-size: 1.4rem;
  }

  .description-text {
    font-size: 0.9rem;
    color: #8f9aa8;
    margin-top: -10px;
    margin-bottom: 20px;
    line-height: 1.4;
  }

  /* Forms styling */
  .form-group {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 20px;
  }

  .form-row-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
  }

  label {
    font-size: 0.85rem;
    font-weight: 600;
    color: #a0aec0;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .input-container {
    display: flex;
    background: rgba(10, 11, 16, 0.8);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    overflow: hidden;
    transition: border-color 0.2s;
  }

  .input-container:focus-within {
    border-color: #aa3bff;
    box-shadow: 0 0 10px rgba(170, 59, 255, 0.2);
  }

  input, select {
    background: rgba(10, 11, 16, 0.8);
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: #ffffff;
    padding: 12px 16px;
    font-size: 0.95rem;
    border-radius: 8px;
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
    box-sizing: border-box;
  }

  input:focus, select:focus {
    border-color: #aa3bff;
    box-shadow: 0 0 8px rgba(170, 59, 255, 0.2);
  }

  .input-container input {
    border: none;
    flex-grow: 1;
    background: transparent;
  }

  .type-select {
    border: none;
    background: rgba(255, 255, 255, 0.05);
    border-left: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 0;
    color: #a0aec0;
    font-weight: 600;
    padding: 0 12px;
    cursor: pointer;
  }

  .primary-select {
    width: 100%;
  }

  .font-mono {
    font-family: 'JetBrains Mono', monospace;
  }

  /* Buttons */
  .actions-area {
    margin-top: 24px;
  }

  .btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    width: 100%;
    padding: 14px 20px;
    font-size: 1rem;
    font-weight: 700;
    border-radius: 10px;
    cursor: pointer;
    border: none;
    transition: all 0.2s ease;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .btn-primary {
    background: linear-gradient(135deg, #aa3bff, #61dafb);
    color: #ffffff;
  }

  .btn-primary:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 5px 15px rgba(170, 59, 255, 0.4);
  }

  .btn-primary:active {
    transform: translateY(1px);
  }

  .btn-glow {
    position: relative;
    overflow: hidden;
  }

  .btn-glow::after {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: linear-gradient(45deg, transparent, rgba(255, 255, 255, 0.1), transparent);
    transform: rotate(45deg);
    transition: 0.5s;
    opacity: 0;
  }

  .btn-glow:hover::after {
    left: 120%;
    opacity: 1;
  }

  .btn-danger {
    background: linear-gradient(135deg, #ff416c, #ff4b2b);
    color: white;
    box-shadow: 0 0 15px rgba(255, 75, 43, 0.3);
  }

  .btn-danger:hover {
    box-shadow: 0 0 25px rgba(255, 75, 43, 0.5);
    transform: translateY(-1px);
  }

  .btn-pulse {
    animation: danger-pulse 2s infinite;
  }

  .btn-secondary {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: #ffffff;
    padding: 10px 16px;
    font-size: 0.85rem;
  }

  .btn-secondary:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.1);
    border-color: rgba(255, 255, 255, 0.2);
  }

  /* Test Vector Gen styling */
  .generator-controls {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .input-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  @media (min-width: 600px) {
    .input-grid {
      grid-template-columns: 2fr 1fr 1fr 1.5fr;
    }
  }

  .input-grid label {
    font-size: 0.75rem;
    margin-bottom: 4px;
    display: block;
  }

  .input-grid input, .input-grid select {
    width: 100%;
    padding: 8px 12px;
    font-size: 0.85rem;
  }

  /* Validation Error */
  .validation-error {
    background: rgba(255, 75, 43, 0.1);
    border: 1px solid rgba(255, 75, 43, 0.3);
    border-radius: 8px;
    padding: 12px 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 20px;
    color: #ff6b6b;
  }

  .validation-error p {
    margin: 0;
    font-size: 0.85rem;
    font-weight: 500;
  }

  /* Monitor Panel */
  .flex-between {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .flex-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .running-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.85rem;
    color: #61dafb;
    font-weight: 600;
  }

  .spinner-small {
    width: 16px;
    height: 16px;
    border: 2px solid rgba(97, 218, 251, 0.2);
    border-top-color: #61dafb;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  .empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #6b7280;
  }

  .empty-icon {
    font-size: 3rem;
    margin-bottom: 16px;
    opacity: 0.5;
  }

  .empty-state h3 {
    color: #ffffff;
    margin: 0 0 8px;
    font-size: 1.1rem;
  }

  .empty-state p {
    font-size: 0.9rem;
    max-width: 320px;
    margin: 0 auto;
  }

  /* Realtime stats dashboard */
  .monitor-dashboard {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .global-stats {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }

  .stat-box {
    background: rgba(10, 11, 16, 0.5);
    border: 1px solid rgba(255, 255, 255, 0.03);
    padding: 16px;
    border-radius: 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .stat-box .label {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: #718096;
    font-weight: 600;
  }

  .stat-box .value {
    font-size: 1.5rem;
    font-weight: 700;
    color: #ffffff;
  }

  .worker-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .worker-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.04);
    transition: all 0.3s;
  }

  .worker-row.status-running {
    border-color: rgba(97, 218, 251, 0.3);
    background: rgba(97, 218, 251, 0.02);
  }

  .worker-row.status-found {
    border-color: rgba(72, 187, 120, 0.5);
    background: rgba(72, 187, 120, 0.05);
    box-shadow: 0 0 15px rgba(72, 187, 120, 0.1);
  }

  .worker-row.status-completed {
    opacity: 0.6;
    background: rgba(255, 255, 255, 0.01);
  }

  .worker-row.status-cancelled {
    opacity: 0.5;
  }

  .worker-meta {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .worker-name {
    font-weight: 700;
    color: #ffffff;
    font-size: 0.95rem;
  }

  .worker-details {
    font-size: 0.75rem;
    color: #718096;
  }

  .worker-state-col {
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .worker-timer {
    font-size: 0.9rem;
    color: #a0aec0;
    min-width: 50px;
    text-align: right;
  }

  /* Status badges */
  .status-badge {
    font-size: 0.7rem;
    font-weight: 800;
    padding: 3px 8px;
    border-radius: 4px;
    letter-spacing: 0.5px;
  }

  .badge-running {
    background: rgba(97, 218, 251, 0.2);
    color: #61dafb;
    animation: status-pulse 1.5s infinite;
  }

  .badge-completed {
    background: rgba(255, 255, 255, 0.1);
    color: #a0aec0;
  }

  .badge-found {
    background: rgba(72, 187, 120, 0.2);
    color: #48bb78;
  }

  .badge-cancelled {
    background: rgba(237, 137, 54, 0.15);
    color: #ed8936;
  }

  .badge-error {
    background: rgba(245, 101, 101, 0.2);
    color: #f56565;
  }

  /* Results styling */
  .results-panel {
    margin-top: 10px;
    animation: slide-up 0.4s cubic-bezier(0.16, 1, 0.3, 1);
  }

  .result-success-box {
    display: flex;
    gap: 20px;
    background: linear-gradient(135deg, rgba(72, 187, 120, 0.1), rgba(97, 218, 251, 0.1));
    border: 1px solid rgba(72, 187, 120, 0.3);
    padding: 20px;
    border-radius: 12px;
    box-shadow: 0 10px 30px rgba(72, 187, 120, 0.15);
  }

  .result-icon {
    font-size: 2.2rem;
    align-self: flex-start;
  }

  .result-text-area {
    flex-grow: 1;
  }

  .result-text-area h3 {
    margin: 0 0 12px;
    color: #ffffff;
    font-size: 1.15rem;
    font-weight: 700;
  }

  .result-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 10px;
  }

  @media (min-width: 500px) {
    .result-grid {
      grid-template-columns: 1fr 1fr;
    }
  }

  .res-item {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .res-lbl {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: #718096;
    font-weight: 600;
  }

  .res-val {
    font-size: 1.1rem;
    font-weight: 700;
    color: #ffffff;
  }

  .highlight-blue {
    color: #61dafb;
  }

  .highlight-green {
    color: #48bb78;
    font-size: 1.3rem;
  }

  .result-fail-box {
    display: flex;
    gap: 20px;
    background: rgba(245, 101, 101, 0.1);
    border: 1px solid rgba(245, 101, 101, 0.3);
    padding: 20px;
    border-radius: 12px;
  }

  .result-fail-box h3 {
    margin: 0 0 6px;
    color: #ff6b6b;
    font-size: 1.15rem;
  }

  .result-fail-box p {
    margin: 0;
    font-size: 0.9rem;
    color: #a0aec0;
    line-height: 1.4;
  }

  /* Animations */
  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  @keyframes status-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.6; }
  }

  @keyframes danger-pulse {
    0%, 100% { box-shadow: 0 0 15px rgba(255, 75, 43, 0.3); }
    50% { box-shadow: 0 0 25px rgba(255, 75, 43, 0.6); }
  }

  @keyframes slide-up {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }

  /* Readme card styles */
  .readme-card {
    border-left: 4px solid #aa3bff;
  }

  .readme-text {
    font-size: 0.95rem;
    color: #a0aec0;
    line-height: 1.6;
    margin: 0 0 16px;
  }

  .readme-text strong {
    color: #ffffff;
  }

  .readme-footer {
    display: flex;
    justify-content: flex-start;
    margin-top: 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    padding-top: 16px;
  }

  .github-btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    width: auto;
    font-size: 0.85rem;
    text-transform: none;
    letter-spacing: normal;
  }

  .gh-icon {
    flex-shrink: 0;
  }
</style>
