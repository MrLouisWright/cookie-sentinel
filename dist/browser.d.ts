/**
 * Visit URLs in a headless browser and collect cookies (including HttpOnly and JS-set).
 * @param {string[]} urls
 * @param {{ engine?: BrowserEngine, headers?: Record<string,string>, timeout?: number, waitUntil?: string }} opts
 */
export function collectBrowser(urls: string[], { engine, headers, timeout, waitUntil }?: {
    engine?: BrowserEngine;
    headers?: Record<string, string>;
    timeout?: number;
    waitUntil?: string;
}): Promise<{
    observations: any[];
    targets: {
        url: string;
        finalUrl: any;
        engine: string;
    }[];
}>;
export type BrowserEngine = "playwright" | "puppeteer";
