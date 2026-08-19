/* tslint:disable */
/* eslint-disable */

/**
 * The artifacts an Add Commit produces: the public Commit message, the
 * Welcome for the added member, and the resulting group state markers the
 * delivery plane records.
 */
export class AddMemberOutput {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    commit: Uint8Array;
    confirmed_transcript_hash: Uint8Array;
    epoch: bigint;
    welcome: Uint8Array;
}

export class MlsClient {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Add a member by their serialized KeyPackage: returns the public
     * Commit, the member's Welcome, and the post-merge group markers.
     */
    addMember(group_id: Uint8Array, key_package: Uint8Array): AddMemberOutput;
    /**
     * Create a new group under the caller-chosen group id.
     */
    createGroup(group_id: Uint8Array): void;
    credentialLabel(): string;
    /**
     * Serialize the whole client - storage map, label, and signature
     * public key - as a versioned JSON snapshot for host persistence.
     */
    exportState(): string;
    /**
     * Serialized MLS KeyPackage message (profile ciphersuite 0x0001).
     */
    generateKeyPackage(): Uint8Array;
    groupConfirmedTranscriptHash(group_id: Uint8Array): Uint8Array;
    groupEpoch(group_id: Uint8Array): bigint;
    /**
     * Rebuild a client from an `export_state` snapshot.
     */
    static importState(json: string): MlsClient;
    /**
     * Join a group from a serialized Welcome; returns the group id.
     */
    joinFromWelcome(welcome: Uint8Array): Uint8Array;
    /**
     * Create a fresh client identity under the given synthetic label
     * (bounded lowercase ASCII; the host derives it from the installation
     * id, never from PII).
     */
    constructor(label: string);
    /**
     * Open a PrivateMessage application payload from another member.
     */
    openApplication(group_id: Uint8Array, message: Uint8Array): Uint8Array;
    /**
     * Process and merge another member's Commit.
     */
    processCommit(group_id: Uint8Array, commit: Uint8Array): void;
    /**
     * Seal an application payload into a PrivateMessage.
     */
    sealApplication(group_id: Uint8Array, plaintext: Uint8Array): Uint8Array;
    /**
     * Raw 32-byte Ed25519 signature public key of this identity.
     */
    signaturePublicKey(): Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_addmemberoutput_free: (a: number, b: number) => void;
    readonly __wbg_get_addmemberoutput_commit: (a: number, b: number) => void;
    readonly __wbg_get_addmemberoutput_confirmed_transcript_hash: (a: number, b: number) => void;
    readonly __wbg_get_addmemberoutput_epoch: (a: number) => bigint;
    readonly __wbg_get_addmemberoutput_welcome: (a: number, b: number) => void;
    readonly __wbg_mlsclient_free: (a: number, b: number) => void;
    readonly __wbg_set_addmemberoutput_commit: (a: number, b: number, c: number) => void;
    readonly __wbg_set_addmemberoutput_confirmed_transcript_hash: (a: number, b: number, c: number) => void;
    readonly __wbg_set_addmemberoutput_epoch: (a: number, b: bigint) => void;
    readonly __wbg_set_addmemberoutput_welcome: (a: number, b: number, c: number) => void;
    readonly mlsclient_addMember: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly mlsclient_createGroup: (a: number, b: number, c: number, d: number) => void;
    readonly mlsclient_credentialLabel: (a: number, b: number) => void;
    readonly mlsclient_exportState: (a: number, b: number) => void;
    readonly mlsclient_generateKeyPackage: (a: number, b: number) => void;
    readonly mlsclient_groupConfirmedTranscriptHash: (a: number, b: number, c: number, d: number) => void;
    readonly mlsclient_groupEpoch: (a: number, b: number, c: number, d: number) => void;
    readonly mlsclient_importState: (a: number, b: number, c: number) => void;
    readonly mlsclient_joinFromWelcome: (a: number, b: number, c: number, d: number) => void;
    readonly mlsclient_new: (a: number, b: number, c: number) => void;
    readonly mlsclient_openApplication: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly mlsclient_processCommit: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly mlsclient_sealApplication: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly mlsclient_signaturePublicKey: (a: number, b: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export3: (a: number, b: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number, d: number) => number;
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
