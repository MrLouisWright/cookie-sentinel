/** Extract links from HTML. */
export function extractLinks(html: any, baseUrl: any, { sameOrigin }?: {
    sameOrigin?: boolean;
}): any[];
/**
 * Breadth-first crawl from seed URLs (same-origin by default).
 */
export function discoverPages(seeds: any, { maxPages, maxDepth, sameOrigin, headers, timeout, insecure, maxRedirects, jar, concurrency, allowPath, denyPath, }?: {
    maxPages?: number;
    maxDepth?: number;
    sameOrigin?: boolean;
    headers?: {};
    jar?: boolean;
    concurrency?: number;
}): Promise<{
    urls: any[];
    pages: any[];
    errors: any[];
}>;
/** Seeds plus discovered pages, expanded with optional paths. */
export function mergeCrawlTargets(seeds: any, discoveredUrls: any, paths?: any[]): string[];
