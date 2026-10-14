/** Parse a JSON headers file: either a flat object or { headers: {...} }. */
export function loadHeadersFile(path: any): any;
/**
 * Parse cookies from a file: JSON array/object, "name=value" lines, or Netscape cookie jar format.
 * Returns a single Cookie header value.
 */
export function loadCookiesFile(path: any): any;
/** Merge Cookie header into a headers object. */
export function mergeCookieHeader(headers: any, cookieHeader: any): any;
/**
 * Optional scripted login before crawling/auditing.
 * @param {object} login - { url, method?, headers?, body?, expectStatus?, saveCookies? }
 * @param {object} fetchOpts - passed to collect()
 * @returns {Promise<{ headers: Record<string,string>, result: object }>}
 */
export function runLogin(login: object, fetchOpts?: object): Promise<{
    headers: Record<string, string>;
    result: object;
}>;
