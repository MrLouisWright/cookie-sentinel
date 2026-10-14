export function formatText(report: any, { color, failOn }?: {
    color?: boolean;
}): string;
export function formatJson(report: any): string;
export function formatSarif(report: any, { version }?: {
    version?: string;
}): string;
export function formatMarkdown(report: any, { failOn }?: {}): string;
