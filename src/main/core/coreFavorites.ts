import type { TunnelServer } from "../../shared/contracts";
import { canonicalNodeList, parseNodeList, reconcileFavorites, serversByNode, unionNodeLists } from "../platform/favoriteNodes";
import { isFavoritesAnswer, isNodeListAnswer, type FavoritesAnswer } from "./coreGuards";
import type { RustCore } from "./rustCore";

const RECONCILE = "favoriteNodes.reconcile";
const UNION = "favoriteNodes.unionNodeLists";

/**
 * The favourites of this computer and the account's node list brought together
 * (favoriteNodes.ts) through the Rust core: the account list to store and the
 * local favourites as they are now.
 */
export function reconcileFavoritesWithCore(
  core: RustCore,
  account: string | null,
  reconciledLocal: ReadonlySet<string>,
  local: readonly string[],
  servers: readonly TunnelServer[],
): { nodes: string; local: Set<string> } {
  const typescript = (): FavoritesAnswer => {
    const result = reconcileFavorites({ nodes: parseNodeList(account), reconciledLocal: new Set(reconciledLocal) }, new Set(local), serversByNode(servers));
    return { nodes: canonicalNodeList(result.nodes), local: [...result.local] };
  };
  if (core.mode === "ts" || !core.has(RECONCILE)) {
    const result = typescript();
    return { nodes: result.nodes, local: new Set(result.local) };
  }
  const input = { nodes: account, reconciledLocal: [...reconciledLocal], local, servers };
  const answer = core.run(RECONCILE, input, typescript, isFavoritesAnswer);
  return { nodes: answer.nodes, local: new Set(answer.local) };
}

/** Both node lists joined, through the Rust core. */
export function unionNodeListsWithCore(core: RustCore, first: string, second: string): string {
  if (core.mode === "ts" || !core.has(UNION)) return unionNodeLists(first, second);
  return core.run(UNION, { first, second }, () => unionNodeLists(first, second), isNodeListAnswer);
}
