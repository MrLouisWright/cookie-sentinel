/** @returns {object|null} */
export function lookupOpenCookieDatabase(name: any): object | null;
/** Registrable domain approximation (good enough for audit classification). */
export function registrableDomain(host: any): string;
/** @param {string} pageUrl @param {string|undefined} cookieDomainAttr @param {object|null} ocdb */
export function cookieParty(pageUrl: string, cookieDomainAttr: string | undefined, ocdb: object | null): "third-party" | "unknown" | "first-party";
/** @param {string|undefined} category */
export function purposeFromCategory(category: string | undefined): "unknown" | "tracking" | "essential";
/**
 * Classify a cookie for privacy/consent reporting.
 * @param {{ name: string, attrs?: { domain?: string } }} cookie
 * @param {string} pageUrl
 */
export function classifyCookie(cookie: {
    name: string;
    attrs?: {
        domain?: string;
    };
}, pageUrl: string): {
    party: string;
    purpose: string;
    category: any;
    vendor: any;
    retentionPeriod: any;
    openCookieDatabase: {
        name: any;
        vendor: any;
        category: any;
    };
};
export function databaseMeta(): any;
export type CookieParty = "first-party" | "third-party" | "unknown";
export type CookiePurpose = "essential" | "tracking" | "unknown";
