export default function takeNWidthWidth(s: string, screenWidth: number, truncStart?: number): string {
    // code walkthrough in ../components/CodeTruncator.tsx
    if (!!truncStart && s.length < 70) {
        let num = truncStart / s.length
        let m = (screenWidth / num)
            if (s.length > m) {
                return `${s.substring(0, m)}…`
            } else {
                return `${s.substring(0, m)}`
            }
    } else if(s.length > 70) {
    let mLong = (screenWidth / (screenWidth / (screenWidth / 15)))
        return `${s.substring(0, mLong)}…`
    } else {
        return s
    }
}