/** Parse one Set-Cookie header value. Returns null for unparseable input. */
export function parseSetCookie(header: any): {
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
/** Lifetime in seconds (Max-Age wins over Expires), null for session cookies. */
export function lifetimeSeconds(cookie: any, now?: number): any;
export function isDeletion(cookie: any, now?: number): boolean;
/** Split a folded "a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT, b=2" header into cookies. */
export function splitCookiesString(str: any): any;
