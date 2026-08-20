import {
  loadBendystrawPreviewConfig,
  type BendystrawPreviewConfig,
} from "./config.server";

/**
 * Discovery over the bendystraw v6 indexer: given a wallet, the projects
 * it has paid (potential support chats as a customer) and the projects it
 * owns (potential chats with its own customers). Public chain data — no
 * auth. The mainnet endpoint indexes every mainnet chain (1/10/8453/42161)
 * in one query; chainId comes back per row.
 */

export interface DiscoveredProject {
  readonly chainId: number;
  readonly projectId: number;
  readonly name: string | null;
  readonly logoUri: string | null;
  readonly isRevnet: boolean;
}

export interface CustomerProject extends DiscoveredProject {
  readonly volume: string;
  readonly paymentsCount: number;
}

export interface OwnerProject extends DiscoveredProject {
  readonly payerCount: number;
}

export interface WalletDiscovery {
  readonly asCustomer: readonly CustomerProject[];
  readonly asOwner: readonly OwnerProject[];
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const MAX_PROJECTS = 24;

type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export class BendystrawDiscoveryAdapter {
  readonly #config: BendystrawPreviewConfig;
  readonly #fetch: FetchLike;

  constructor(options?: {
    config?: BendystrawPreviewConfig;
    fetchImpl?: FetchLike;
  }) {
    this.#config = options?.config ?? loadBendystrawPreviewConfig();
    this.#fetch = options?.fetchImpl ?? globalThis.fetch;
  }

  async discover(address: string): Promise<WalletDiscovery> {
    if (!ADDRESS.test(address)) {
      return { asCustomer: [], asOwner: [] };
    }
    const lower = address.toLowerCase();
    const endpoint = this.#config.endpoints.mainnet;

    const [payers, owned] = await Promise.all([
      this.#query<{
        projectPayers: {
          items: {
            chainId: number;
            projectId: number;
            volume: string;
            paymentsCount: number;
          }[];
        };
      }>(
        endpoint,
        `query($a: String!){ projectPayers(where:{address:$a}, limit:${MAX_PROJECTS}){ items { chainId projectId volume paymentsCount } } }`,
        { a: lower },
      ),
      this.#query<{
        projects: {
          items: {
            chainId: number;
            projectId: number;
            name: string | null;
            logoUri: string | null;
            isRevnet: boolean | null;
          }[];
        };
      }>(
        endpoint,
        `query($a: String!){ projects(where:{owner:$a, version:6}, limit:${MAX_PROJECTS}){ items { chainId projectId name logoUri isRevnet } } }`,
        { a: lower },
      ),
    ]);

    const payerItems = payers?.projectPayers.items ?? [];
    const ownedItems = owned?.projects.items ?? [];

    // Resolve names/logos for the paid projects in one aliased query.
    const meta = await this.#resolveMeta(endpoint, payerItems);

    const asCustomer: CustomerProject[] = payerItems.map((item) => {
      const key = `${item.chainId}:${item.projectId}`;
      return {
        chainId: item.chainId,
        projectId: item.projectId,
        name: meta.get(key)?.name ?? null,
        logoUri: meta.get(key)?.logoUri ?? null,
        isRevnet: meta.get(key)?.isRevnet ?? false,
        volume: item.volume,
        paymentsCount: item.paymentsCount,
      };
    });

    const asOwner: OwnerProject[] = await Promise.all(
      ownedItems.map(async (item) => ({
        chainId: item.chainId,
        projectId: item.projectId,
        name: item.name,
        logoUri: item.logoUri,
        isRevnet: Boolean(item.isRevnet),
        payerCount: await this.#payerCount(endpoint, item.chainId, item.projectId),
      })),
    );

    return { asCustomer, asOwner };
  }

  async #resolveMeta(
    endpoint: string,
    items: { chainId: number; projectId: number }[],
  ): Promise<Map<string, { name: string | null; logoUri: string | null; isRevnet: boolean }>> {
    const out = new Map<
      string,
      { name: string | null; logoUri: string | null; isRevnet: boolean }
    >();
    if (items.length === 0) return out;
    const aliases = items
      .map(
        (item, index) =>
          `p${index}: project(chainId:${item.chainId}, projectId:${item.projectId}, version:6){ name logoUri isRevnet }`,
      )
      .join("\n");
    const data = await this.#query<Record<string, {
      name: string | null;
      logoUri: string | null;
      isRevnet: boolean | null;
    } | null>>(endpoint, `query{ ${aliases} }`, {});
    if (!data) return out;
    items.forEach((item, index) => {
      const value = data[`p${index}`];
      out.set(`${item.chainId}:${item.projectId}`, {
        name: value?.name ?? null,
        logoUri: value?.logoUri ?? null,
        isRevnet: Boolean(value?.isRevnet),
      });
    });
    return out;
  }

  async #payerCount(
    endpoint: string,
    chainId: number,
    projectId: number,
  ): Promise<number> {
    const data = await this.#query<{
      projectPayers: { totalCount?: number; items: unknown[] };
    }>(
      endpoint,
      `query{ projectPayers(where:{chainId:${chainId}, projectId:${projectId}}, limit:1){ totalCount items { address } } }`,
      {},
    );
    return data?.projectPayers.totalCount ?? data?.projectPayers.items.length ?? 0;
  }

  async #query<T>(
    endpoint: string,
    query: string,
    variables: Record<string, unknown>,
  ): Promise<T | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#config.timeoutMs);
    try {
      const response = await this.#fetch(endpoint, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json; charset=utf-8",
        },
        body: JSON.stringify({ query, variables }),
        signal: controller.signal,
      });
      if (!response.ok) return null;
      const body = (await response.json()) as { data?: T; errors?: unknown };
      if (body.errors || !body.data) return null;
      return body.data;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}
