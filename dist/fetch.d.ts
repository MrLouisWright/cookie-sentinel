/**
 * Fetch a URL following redirects; returns { url, finalUrl, hops: [{url,status,location,setCookie:[]}], observations }.
 * Cookies received along the way are replayed on later hops to the same host (simple jar) unless jar === false.
 */
export function collect(url: any, { headers, maxRedirects, timeout, insecure, jar, method, body, readBody }?: {
    headers?: {};
    maxRedirects?: number;
    jar?: boolean;
    readBody?: boolean;
}): Promise<{
    url: any;
    finalUrl: any;
    hops: {
        url: any;
        status: any;
        location: string;
        setCookie: any;
        body: any;
    }[];
    observations: {
        cookie: {
            name: string;
            value: string;
            attrs: {
                secure: boolean;
                httpOnly: boolean;
                partitioned: boolean;
                sameSite: any;
                domain: any;
                path: any;
                expires: any;
                maxAge: any;
                unknown: any[];
            };
            raw: string;
        };
        url: any;
        status: any;
        hop: number;
        source: any;
    }[];
    html: any;
}>;
/** Expand base URLs × paths into a de-duplicated target list. */
export function expandTargets(urls: any, paths?: any[]): string[];
