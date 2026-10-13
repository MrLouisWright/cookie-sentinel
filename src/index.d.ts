export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface ParsedCookie {
  name: string; value: string; raw: string;
  attrs: { secure: boolean; httpOnly: boolean; partitioned: boolean; sameSite?: string; domain?: string; path?: string; expires?: Date; expiresRaw?: string; maxAge?: number; unknown: string[] };
}
export interface Finding { rule: string; severity: Severity; cookie: string; url: string; message: string; fix: string; setCookie: string; sessionLike?: boolean; hop?: number }
export interface AllowEntry { rule?: string; cookie?: string; url?: string; reason?: string }
export interface Config {
  allow?: Array<AllowEntry | string>;
  severity?: Record<string, Severity | 'off'>;
  sessionPatterns?: string[]; notSessionPatterns?: string[]; replaceSessionPatterns?: boolean;
  maxAgeDays?: number; sessionMaxAgeDays?: number; largeBytes?: number; flagBroadPath?: boolean; thirdParty?: boolean;
  failOn?: Severity | 'none'; headers?: Record<string, string>; urls?: string[]; paths?: string[]; origin?: string; insecure?: boolean; now?: number;
}
export interface Report {
  tool: 'cookie-sentinel'; generatedAt: string; targets: any[];
  cookies: Array<{ name: string; url: string; hop?: number; sessionLike: boolean; setCookie: string }>;
  findings: Finding[]; suppressed: Array<Finding & { allowedBy: unknown }>;
  counts: Record<Severity, number>; errors: Array<{ url: string; error: string }>;
}
export const SEVERITIES: Severity[];
export const RULES: Record<string, { severity: Severity; title: string }>;
export function parseSetCookie(header: string): ParsedCookie | null;
export function splitCookiesString(s: string | string[]): string[];
export function lifetimeSeconds(c: ParsedCookie, now?: number): number | null;
export function isSessionLike(name: string, opts: any): boolean;
export function expandTargets(urls: string[], paths?: string[]): string[];
export function collect(url: string, opts?: { headers?: Record<string, string>; maxRedirects?: number; timeout?: number; insecure?: boolean; jar?: boolean }): Promise<any>;
export function auditSetCookies(input: string | string[], opts?: { origin?: string; config?: Config }): Report;
export function auditUrls(urls: string[], opts?: { paths?: string[]; headers?: Record<string, string>; config?: Config; maxRedirects?: number; timeout?: number; insecure?: boolean; jar?: boolean; concurrency?: number }): Promise<Report>;
export function auditObservations(obs: Array<{ cookie: ParsedCookie; url: string; hop?: number }>, config?: Config, meta?: any): Report;
export function exceeds(report: Report, failOn?: Severity | 'none'): boolean;
export function formatText(r: Report, o?: { color?: boolean; failOn?: string }): string;
export function formatJson(r: Report): string;
export function formatSarif(r: Report, o?: { version?: string }): string;
export function formatMarkdown(r: Report, o?: { failOn?: string }): string;
