export function compilePatterns(list: any): any;
export function isSessionLike(name: any, opts: any): any;
/**
 * Audit a list of observations: { cookie, url, status?, hop? }.
 * Returns raw findings (before severity overrides / allowlist).
 */
export function runRules(observations: any, opts: any): {
    rule: string;
    severity: string;
    cookie: any;
    url: any;
    message: string;
    fix: string;
    setCookie: any;
}[];
export const SEVERITIES: string[];
export function rank(s: any): number;
export const DEFAULT_SESSION_PATTERNS: string[];
export const DEFAULT_NOT_SESSION_PATTERNS: string[];
export const RULES: {
    'missing-secure': {
        severity: string;
        title: string;
    };
    'cookie-over-http': {
        severity: string;
        title: string;
    };
    'missing-httponly': {
        severity: string;
        title: string;
    };
    'samesite-missing': {
        severity: string;
        title: string;
    };
    'samesite-none': {
        severity: string;
        title: string;
    };
    'samesite-none-insecure': {
        severity: string;
        title: string;
    };
    'samesite-invalid': {
        severity: string;
        title: string;
    };
    'host-prefix': {
        severity: string;
        title: string;
    };
    'secure-prefix': {
        severity: string;
        title: string;
    };
    'broad-domain': {
        severity: string;
        title: string;
    };
    'domain-mismatch': {
        severity: string;
        title: string;
    };
    'broad-path': {
        severity: string;
        title: string;
    };
    'long-expiry': {
        severity: string;
        title: string;
    };
    'large-cookie': {
        severity: string;
        title: string;
    };
    'sensitive-jwt': {
        severity: string;
        title: string;
    };
    'jwt-alg-none': {
        severity: string;
        title: string;
    };
    'sensitive-email': {
        severity: string;
        title: string;
    };
    'duplicate-cookie': {
        severity: string;
        title: string;
    };
    'partitioned-insecure': {
        severity: string;
        title: string;
    };
    'partitioned-misuse': {
        severity: string;
        title: string;
    };
};
