/* tslint:disable */
/* eslint-disable */

/**
 * A wrapper around various common primitives used for PBKDF2.
 * Implements a name and the closure to compute the values.
 * This will later on be a userful abstraction when differentiating between webassembly and multithreaded code.
 */
export enum HashPrimitive {
    HMACSHA1 = 0,
    HMACSHA224 = 1,
    HMACSHA256 = 2,
    HMACSHA384 = 3,
    HMACSHA512 = 4,
}

export class Pbkdf2Parameters {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    iterations: number;
    primitive: HashPrimitive;
}

export function identify_iterations(password: Uint8Array, hash: Uint8Array, salt: Uint8Array, primitive: HashPrimitive, max?: number | null): number | undefined;

export function primitive_name(p: HashPrimitive): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_get_pbkdf2parameters_iterations: (a: number) => number;
    readonly __wbg_get_pbkdf2parameters_primitive: (a: number) => number;
    readonly __wbg_pbkdf2parameters_free: (a: number, b: number) => void;
    readonly __wbg_set_pbkdf2parameters_iterations: (a: number, b: number) => void;
    readonly __wbg_set_pbkdf2parameters_primitive: (a: number, b: number) => void;
    readonly identify_iterations: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly primitive_name: (a: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
