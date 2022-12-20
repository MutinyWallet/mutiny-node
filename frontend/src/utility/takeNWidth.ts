export default function takeNWidthWidth(s: string, n: number, screenWidth: number): string {
    let m = (screenWidth * n)
    return `${s.substring(0, m)}…`
}