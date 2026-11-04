import { verifyEndpointsDocument, type ServiceEndpointsDocument } from "../platform/serviceEndpoints";
import type { RustCore } from "./rustCore";

function isDocument(value: unknown): value is ServiceEndpointsDocument | null {
  if (value === null) return true;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  // URL.href can be longer than its source after escaping Unicode.
  const urls = (item: unknown): item is string[] => Array.isArray(item) && item.length <= 8
    && item.every((url: unknown) => typeof url === "string" && url.length <= 4096 && url.startsWith("https://"));
  return "sequence" in value && typeof value.sequence === "number" && Number.isSafeInteger(value.sequence) && value.sequence >= 1
    && "apiOrigins" in value && urls(value.apiOrigins) && value.apiOrigins.length > 0
    && "configUrls" in value && urls(value.configUrls)
    && "webOrigin" in value && typeof value.webOrigin === "string" && value.webOrigin.length <= 300 && value.webOrigin.startsWith("https://");
}

/** The publisher key is built into both implementations; downloaded keys are never trusted. */
export class CoreEndpoints {
  constructor(private readonly current: () => RustCore) {}

  verify(body: Buffer, signature: string): ServiceEndpointsDocument | null {
    // Refuse oversized data before allocating a JSON/base64 bridge message.
    if (body.length > 16 * 1024 || signature.length > 512) return null;
    return this.current().run("serviceEndpoints.verifyEndpointsDocument", { body: body.toString("base64"), signature },
      () => verifyEndpointsDocument(body, signature), isDocument);
  }
}
