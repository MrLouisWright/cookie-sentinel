export function resolveOptions(config?: {}): {
    sessionRe: any;
    notSessionRe: any;
    maxAgeDays: number;
    sessionMaxAgeDays: number;
    largeBytes: number;
    flagBroadPath: boolean;
    thirdParty: boolean;
};
/** Apply per-rule severity overrides ("off" disables) and the allowlist. */
export function applyConfig(findings: any, config?: {}): {
    findings: any[];
    suppressed: any[];
};
/** Audit already-collected observations ([{cookie,url}]) and build a report. */
export function auditObservations(observations: any, config?: {}, meta?: {}): {
    tool: string;
    generatedAt: string;
    targets: any;
    crawl: any;
    browser: any;
    openCookieDatabase: any;
    cookies: any;
    classificationSummary: {
        firstParty: number;
        thirdParty: number;
        unknownParty: number;
        essential: number;
        tracking: number;
        unknownPurpose: number;
        catalogued: number;
    };
    findings: any[];
    suppressed: any[];
    counts: {
        [k: string]: number;
    };
    errors: any;
};
/** Audit raw Set-Cookie header lines (offline). `origin` gives the URL context. */
export function auditSetCookies(input: any, { origin, config }?: {
    origin?: string;
    config?: {};
}): {
    tool: string;
    generatedAt: string;
    targets: any;
    crawl: any;
    browser: any;
    openCookieDatabase: any;
    cookies: any;
    classificationSummary: {
        firstParty: number;
        thirdParty: number;
        unknownParty: number;
        essential: number;
        tracking: number;
        unknownPurpose: number;
        catalogued: number;
    };
    findings: any[];
    suppressed: any[];
    counts: {
        [k: string]: number;
    };
    errors: any;
};
/** Fetch URLs (× paths), optional multi-page crawl and headless browser capture. */
export function auditUrls(urls: any, { paths, headers: headerOverrides, config, maxRedirects, timeout, insecure, jar, concurrency, crawl, browser, }?: {
    paths?: any[];
    headers?: {};
    config?: {};
    concurrency?: number;
}): Promise<{
    tool: string;
    generatedAt: string;
    targets: any;
    crawl: any;
    browser: any;
    openCookieDatabase: any;
    cookies: any;
    classificationSummary: {
        firstParty: number;
        thirdParty: number;
        unknownParty: number;
        essential: number;
        tracking: number;
        unknownPurpose: number;
        catalogued: number;
    };
    findings: any[];
    suppressed: any[];
    counts: {
        [k: string]: number;
    };
    errors: any;
}>;
export function exceeds(report: any, failOn?: string): any;
export namespace DEFAULTS {
    let maxAgeDays: number;
    let sessionMaxAgeDays: number;
    let largeBytes: number;
    let flagBroadPath: boolean;
    let thirdParty: boolean;
}
import { parseSetCookie } from './parse.js';
import { splitCookiesString } from './parse.js';
import { lifetimeSeconds } from './parse.js';
import { RULES } from './rules.js';
import { SEVERITIES } from './rules.js';
import { collect } from './fetch.js';
import { expandTargets } from './fetch.js';
import { isSessionLike } from './rules.js';
import { discoverPages } from './crawl.js';
import { mergeCrawlTargets } from './crawl.js';
import { loadHeadersFile } from './auth.js';
import { loadCookiesFile } from './auth.js';
import { mergeCookieHeader } from './auth.js';
import { runLogin } from './auth.js';
import { classifyCookie } from './classify.js';
import { lookupOpenCookieDatabase } from './classify.js';
import { databaseMeta } from './classify.js';
import { collectBrowser } from './browser.js';
export { parseSetCookie, splitCookiesString, lifetimeSeconds, RULES, SEVERITIES, collect, expandTargets, isSessionLike, discoverPages, mergeCrawlTargets, loadHeadersFile, loadCookiesFile, mergeCookieHeader, runLogin, classifyCookie, lookupOpenCookieDatabase, databaseMeta, collectBrowser };
export { formatText, formatJson, formatSarif, formatMarkdown } from "./report.js";
