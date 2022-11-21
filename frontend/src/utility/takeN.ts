export default function takeN(s: string, n: number): string {
    return `${s.substring(0, n)}…`
}