"use client";

/**
 * The production messaging client: real device enrollment (SIWE wallet
 * proof + non-extractable WebCrypto P-256 possession key), RFC 9449 DPoP
 * on every authenticated call, and typed access to the /v1 API. Private
 * keys never leave WebCrypto; the possession/DPoP key is generated
 * non-extractable and persisted as a CryptoKey in IndexedDB. The initial
 * KeyPackage published at enrollment is a clearly labeled
 * jbm-pre-mls-client/v1 transitional record around the real Ed25519
 * credential key - MLS clients reject and replace it; nothing pretends
 * to be RFC 9420 bytes.
 */

const MEDIA_TYPE = "application/vnd.juicebox.messaging.v1+json";
const DB_NAME = "jbm-messaging-keys";
const STORE = "keys";
const REFRESH_KEY = "jbm-messaging-refresh-v1";
const WALLET_KEY = "jbm-messaging-wallet-v1";

export interface MessagingSession {
  readonly status: "none" | "ready";
  readonly accountId: string | null;
  readonly installationId: string | null;
  readonly walletAddress: string | null;
}

interface KeyRecord {
  readonly authKeyPair: CryptoKeyPair;
  readonly mlsKeyPair: CryptoKeyPair;
  readonly installationId: string;
  readonly accountId: string;
}

let accessToken: string | null = null;
let sessionState: MessagingSession = {
  status: "none",
  accountId: null,
  installationId: null,
  walletAddress: null,
};
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

export function subscribeSession(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getSession(): MessagingSession {
  return sessionState;
}

export function getSessionServerSnapshot(): MessagingSession {
  return { status: "none", accountId: null, installationId: null, walletAddress: null };
}

function openKeyDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error);
  });
}

async function idbSet(key: string, value: unknown): Promise<void> {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const request = db
      .transaction(STORE, "readwrite")
      .objectStore(STORE)
      .put(value, key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromB64url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function lowSSignature(
  key: CryptoKey,
  data: Uint8Array,
): Promise<Uint8Array> {
  const raw = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      data as BufferSource,
    ),
  );
  const order = BigInt(
    "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
  );
  let s = 0n;
  for (const byte of raw.subarray(32)) s = (s << 8n) | BigInt(byte);
  if (s > order / 2n) {
    let flipped = order - s;
    const out = new Uint8Array(raw);
    for (let index = 63; index >= 32; index -= 1) {
      out[index] = Number(flipped & 0xffn);
      flipped >>= 8n;
    }
    return out;
  }
  return raw;
}

async function dpopProof(
  keyPair: CryptoKeyPair,
  method: string,
  url: string,
  bindToken: string,
): Promise<string> {
  const jwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as {
    x: string;
    y: string;
  };
  const normalized = new URL(url, window.location.origin);
  normalized.search = "";
  normalized.hash = "";
  const header = b64url(
    new TextEncoder().encode(
      JSON.stringify({
        typ: "dpop+jwt",
        alg: "ES256",
        jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      }),
    ),
  );
  const ath = b64url(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(bindToken) as BufferSource,
    ),
  );
  const payload = b64url(
    new TextEncoder().encode(
      JSON.stringify({
        htm: method,
        htu: normalized.toString(),
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(),
        ath,
      }),
    ),
  );
  const signature = await lowSSignature(
    keyPair.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${b64url(signature)}`;
}

async function jsonRequest(
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<Response> {
  return fetch(path, {
    method,
    headers: {
      ...(body === undefined ? {} : { "Content-Type": MEDIA_TYPE }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Authenticated /v1 call with DPoP; refreshes once on a 401. */
export async function api(
  method: string,
  path: string,
  body?: unknown,
): Promise<Response> {
  const record = await idbGet<KeyRecord>("device");
  if (!record || !accessToken) {
    const refreshed = await tryRefresh();
    if (!refreshed) return new Response(null, { status: 401 });
  }
  const active = await idbGet<KeyRecord>("device");
  if (!active || !accessToken) return new Response(null, { status: 401 });
  const call = async (): Promise<Response> =>
    jsonRequest(method, path, body, {
      Authorization: `DPoP ${accessToken}`,
      DPoP: await dpopProof(active.authKeyPair, method, path, accessToken!),
    });
  let response = await call();
  if (response.status === 401 && (await tryRefresh())) {
    response = await call();
  }
  return response;
}

async function tryRefresh(): Promise<boolean> {
  const refreshToken = window.localStorage.getItem(REFRESH_KEY);
  const record = await idbGet<KeyRecord>("device");
  if (!refreshToken || !record) return false;
  const response = await jsonRequest(
    "POST",
    "/v1/auth/refresh",
    { refreshToken },
    {
      DPoP: await dpopProof(
        record.authKeyPair,
        "POST",
        "/v1/auth/refresh",
        refreshToken,
      ),
    },
  );
  if (!response.ok) {
    if (response.status === 401) signOutLocal();
    return false;
  }
  const rotated = (await response.json()) as {
    accessToken: string;
    refreshToken: string;
  };
  accessToken = rotated.accessToken;
  window.localStorage.setItem(REFRESH_KEY, rotated.refreshToken);
  sessionState = {
    status: "ready",
    accountId: record.accountId,
    installationId: record.installationId,
    walletAddress: window.localStorage.getItem(WALLET_KEY),
  };
  emit();
  return true;
}

export async function restoreSession(): Promise<void> {
  await tryRefresh();
}

export function signOutLocal(): void {
  accessToken = null;
  window.localStorage.removeItem(REFRESH_KEY);
  sessionState = {
    status: "none",
    accountId: null,
    installationId: null,
    walletAddress: null,
  };
  emit();
}

export async function signOut(): Promise<void> {
  try {
    await api("DELETE", "/v1/auth/session");
  } finally {
    signOutLocal();
  }
}

export type EnrollmentProgress =
  | "allocating"
  | "generating-keys"
  | "awaiting-wallet-signature"
  | "verifying"
  | "done";

/**
 * The full enrollment ceremony against the live service: allocation, key
 * binding, paired SIWE + possession challenges, wallet signature via the
 * connected wallet, and session issuance. Throws with the service's
 * stable reason code on refusal.
 */
export async function enrollDevice(input: {
  walletAddress: string;
  chainId: number;
  signMessage: (message: string) => Promise<string>;
  onProgress?: (step: EnrollmentProgress) => void;
}): Promise<void> {
  const progress = input.onProgress ?? (() => {});
  const walletRef = `eip155:${input.chainId}:${input.walletAddress.toLowerCase()}`;
  const origin = window.location.origin;
  progress("allocating");
  const allocated = await jsonRequest("POST", "/v1/device-enrollments", {
    walletRef,
    proofProfile: "siwe-erc4361-v1",
    client: {
      clientId: "juicebox-messaging-web",
      origin,
      audience: `${origin}/v1`,
    },
    purpose: "enroll-messaging-device",
    scope: {
      kind: "wallet-challenge-scope.v1",
      project: null,
      action: "enroll-messaging-device",
    },
    installationKind: "native",
    platform: "web",
  });
  if (!allocated.ok) {
    throw new Error(await reasonOf(allocated, "enrollment_refused"));
  }
  const allocation = (await allocated.json()) as {
    enrollmentId: string;
    enrollmentResultHandle: string;
  };
  const capability = {
    Authorization: `Enrollment ${allocation.enrollmentResultHandle}`,
  };

  progress("generating-keys");
  const authKeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  let mlsKeyPair: CryptoKeyPair;
  try {
    mlsKeyPair = (await crypto.subtle.generateKey("Ed25519", false, [
      "sign",
    ])) as CryptoKeyPair;
  } catch {
    throw new Error("browser_missing_ed25519");
  }
  const authJwk = (await crypto.subtle.exportKey(
    "jwk",
    authKeyPair.publicKey,
  )) as { x: string; y: string };
  const mlsPublicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", mlsKeyPair.publicKey),
  );
  // Transitional labeled record, NOT MLS bytes; replaced by the MLS client.
  const keyPackageBytes = new Uint8Array([
    ...new TextEncoder().encode("jbm-pre-mls-client/v1 "),
    ...mlsPublicRaw,
  ]);

  const challenged = await jsonRequest(
    "POST",
    `/v1/device-enrollments/${allocation.enrollmentId}/challenges`,
    {
      walletRef,
      installationAuthPublicJwk: {
        kty: "EC",
        crv: "P-256",
        x: authJwk.x,
        y: authJwk.y,
        use: "sig",
        alg: "ES256",
      },
      mlsCredentialPublic: b64url(mlsPublicRaw),
      keyPackage: b64url(keyPackageBytes),
    },
    capability,
  );
  if (!challenged.ok) {
    throw new Error(await reasonOf(challenged, "enrollment_invalid"));
  }
  const challenges = (await challenged.json()) as {
    siweMessage: string;
    possessionChallengeDigest: string;
  };

  progress("awaiting-wallet-signature");
  const walletSignature = await input.signMessage(challenges.siweMessage);
  const possessionSignature = b64url(
    await lowSSignature(
      authKeyPair.privateKey,
      fromB64url(challenges.possessionChallengeDigest),
    ),
  );

  progress("verifying");
  const completed = await jsonRequest(
    "POST",
    `/v1/device-enrollments/${allocation.enrollmentId}/complete`,
    {
      client: { clientId: "juicebox-messaging-web", audience: `${origin}/v1` },
      walletProof: { signature: walletSignature },
      possessionProof: { signature: possessionSignature },
    },
    capability,
  );
  if (!completed.ok) {
    throw new Error(await reasonOf(completed, "enrollment_failed"));
  }
  const issued = (await completed.json()) as {
    accessToken: string;
    refreshToken: string;
    account: { accountId: string };
    installation: { installationId: string };
  };
  await idbSet("device", {
    authKeyPair,
    mlsKeyPair,
    installationId: issued.installation.installationId,
    accountId: issued.account.accountId,
  } satisfies KeyRecord);
  accessToken = issued.accessToken;
  window.localStorage.setItem(REFRESH_KEY, issued.refreshToken);
  window.localStorage.setItem(WALLET_KEY, input.walletAddress.toLowerCase());
  sessionState = {
    status: "ready",
    accountId: issued.account.accountId,
    installationId: issued.installation.installationId,
    walletAddress: input.walletAddress.toLowerCase(),
  };
  progress("done");
  emit();
}

async function reasonOf(response: Response, fallback: string): Promise<string> {
  try {
    const body = (await response.json()) as { reasonCode?: string };
    return body.reasonCode ?? fallback;
  } catch {
    return fallback;
  }
}
