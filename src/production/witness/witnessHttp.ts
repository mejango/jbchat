import { Buffer } from "node:buffer";
import { createPrivateKey, sign as signEd25519, timingSafeEqual } from "node:crypto";
import postgres, { type Sql } from "postgres";
import { createWitnessCore } from "./witnessCore";

const ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const NAMESPACES = new Set(["delivery", "policy", "directory"]);
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/**
 * The witness deployment's HTTP layer. It runs from the same codebase as
 * the delivery service but as a SEPARATE deployment with its own database,
 * signing seed, and submit token (ADR 0002 isolation); on the delivery
 * deployment these variables are absent and every witness route is a
 * fail-closed 404. Write endpoints require the bearer submit token with a
 * timing-safe comparison; transparency reads are public and cacheable.
 */
export type WitnessRuntime =
  | {
      readonly status: "configured";
      readonly core: ReturnType<typeof createWitnessCore>;
      readonly submitToken: Buffer;
    }
  | { readonly status: "unconfigured" };

let runtime: WitnessRuntime | null = null;
let runtimeSql: Sql | null = null;

export function loadWitnessRuntime(
  environment: NodeJS.ProcessEnv = process.env,
): WitnessRuntime {
  if (runtime) return runtime;
  const databaseUrl = environment.JBM_WITNESS_DATABASE_URL;
  const keyId = environment.JBM_WITNESS_KEY_ID;
  const seedValue = environment.JBM_WITNESS_SIGNING_SEED;
  const tokenValue = environment.JBM_WITNESS_SUBMIT_TOKEN;
  if (!databaseUrl || !keyId || !seedValue || !tokenValue) {
    runtime = Object.freeze({ status: "unconfigured" as const });
    return runtime;
  }
  if (!/^postgres(ql)?:\/\//.test(databaseUrl)) {
    throw new TypeError("JBM_WITNESS_DATABASE_URL must be a postgres:// URL.");
  }
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new TypeError("JBM_WITNESS_KEY_ID is not a canonical key ID.");
  }
  const seed = Buffer.from(seedValue, "base64url");
  if (seed.byteLength !== 32) {
    throw new TypeError(
      "JBM_WITNESS_SIGNING_SEED must be 32 base64url-encoded bytes.",
    );
  }
  const submitToken = Buffer.from(tokenValue, "base64url");
  if (submitToken.byteLength < 32) {
    throw new TypeError(
      "JBM_WITNESS_SUBMIT_TOKEN must decode to at least 32 bytes.",
    );
  }
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  runtimeSql = postgres(databaseUrl, { max: 4, onnotice: () => {} });
  runtime = Object.freeze({
    status: "configured" as const,
    core: createWitnessCore({
      sql: runtimeSql,
      signer: Object.freeze({
        witnessKeyId: keyId,
        sign: (digest: Buffer) => signEd25519(null, digest, privateKey),
      }),
    }),
    submitToken,
  });
  return runtime;
}

/** Test hook: clears the memoized runtime so environments can vary. */
export function resetWitnessRuntimeForTesting(): void {
  runtime = null;
  void runtimeSql?.end({ timeout: 1 });
  runtimeSql = null;
}

function notFound(): Response {
  return Response.json(
    { type: "about:blank", title: "not_found", status: 404 },
    { status: 404 },
  );
}

function unauthorized(): Response {
  return Response.json(
    { type: "about:blank", title: "unauthorized", status: 401 },
    { status: 401 },
  );
}

function badRequest(): Response {
  return Response.json(
    { type: "about:blank", title: "invalid_request", status: 400 },
    { status: 400 },
  );
}

function authorizedSubmit(request: Request, submitToken: Buffer): boolean {
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer ([A-Za-z0-9_-]+)$/.exec(header);
  if (!match) return false;
  const presented = Buffer.from(match[1], "base64url");
  return (
    presented.byteLength === submitToken.byteLength &&
    timingSafeEqual(presented, submitToken)
  );
}

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = (await request.json()) as unknown;
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function createWitnessHttpHandlers(): {
  submitExtension: (request: Request) => Promise<Response>;
  reportGossip: (request: Request) => Promise<Response>;
  readCheckpoint: (
    request: Request,
    checkpointId: string,
  ) => Promise<Response>;
  latestCheckpoint: (request: Request) => Promise<Response>;
  consistencyProof: (request: Request) => Promise<Response>;
} {
  return {
    async submitExtension(request: Request): Promise<Response> {
      const active = loadWitnessRuntime();
      if (active.status !== "configured") return notFound();
      if (!authorizedSubmit(request, active.submitToken)) return unauthorized();
      const body = await readJson(request);
      if (!body || typeof body.namespace !== "string") return badRequest();
      try {
        if (body.namespace === "delivery") {
          const result = await active.core.extendDelivery({
            conversationId: String(body.conversationId),
            position: String(body.position),
            previousHeadHash: String(body.previousHeadHash),
            headHash: String(body.headHash),
            signingKeyId: String(body.signingKeyId),
            signature: String(body.signature),
            checkpointReceivedAt: String(body.checkpointReceivedAt),
          });
          return Response.json(result, {
            status: result.status === "witnessed" ? 200 : 409,
          });
        }
        if (body.namespace === "policy" || body.namespace === "directory") {
          const result = await active.core.extendChain(body.namespace, {
            checkpointId: String(body.checkpointId),
            treeSize: String(body.treeSize),
            rootHash: String(body.rootHash),
            previousCheckpointId:
              body.previousCheckpointId === null
                ? null
                : String(body.previousCheckpointId),
            signerKeyId: String(body.signerKeyId),
          });
          return Response.json(result, {
            status: result.status === "witnessed" ? 200 : 409,
          });
        }
        return badRequest();
      } catch {
        return badRequest();
      }
    },

    async reportGossip(request: Request): Promise<Response> {
      const active = loadWitnessRuntime();
      if (active.status !== "configured") return notFound();
      const body = await readJson(request);
      if (!body) return badRequest();
      try {
        const result = await active.core.reportGossip({
          conversationId: String(body.conversationId),
          position: String(body.position),
          headHash: String(body.headHash),
          witnessCheckpointId: String(body.witnessCheckpointId),
        });
        return Response.json(result);
      } catch {
        return badRequest();
      }
    },

    async readCheckpoint(
      _request: Request,
      checkpointId: string,
    ): Promise<Response> {
      const active = loadWitnessRuntime();
      if (active.status !== "configured") return notFound();
      const checkpoint = await active.core
        .readCheckpoint(checkpointId)
        .catch(() => null);
      if (!checkpoint) return notFound();
      return Response.json(checkpoint, {
        headers: { "cache-control": "public, max-age=31536000, immutable" },
      });
    },

    async latestCheckpoint(request: Request): Promise<Response> {
      const active = loadWitnessRuntime();
      if (active.status !== "configured") return notFound();
      const namespace = new URL(request.url).searchParams.get("namespace") ?? "";
      if (!NAMESPACES.has(namespace)) return badRequest();
      const checkpoint = await active.core
        .latestCheckpoint(namespace as "delivery")
        .catch(() => null);
      if (!checkpoint) return notFound();
      return Response.json(checkpoint, {
        headers: { "cache-control": "public, max-age=5" },
      });
    },

    async consistencyProof(request: Request): Promise<Response> {
      const active = loadWitnessRuntime();
      if (active.status !== "configured") return notFound();
      const url = new URL(request.url);
      const namespace = url.searchParams.get("namespace") ?? "";
      const from = url.searchParams.get("from") ?? "";
      const to = url.searchParams.get("to") ?? "";
      if (!NAMESPACES.has(namespace) || !/^\d+$/.test(from) || !/^\d+$/.test(to)) {
        return badRequest();
      }
      const proof = await active.core
        .proveConsistency(namespace as "delivery", from, to)
        .catch(() => null);
      if (!proof) return notFound();
      return Response.json(
        { namespace, from, to, proof },
        {
          headers: { "cache-control": "public, max-age=31536000, immutable" },
        },
      );
    },
  };
}
