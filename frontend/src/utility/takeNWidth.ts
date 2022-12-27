export default function takeNWidthWidth(s: string, screenWidth: number, truncStart?: number): string {
    console.log(screenWidth, s.length)
    if (!!truncStart) {
        let num = truncStart / s.length
        let m = (screenWidth / num)
            if (s.length > m) {
                return `${s.substring(0, m)}…`
            } else {
                return `${s.substring(0, m)}`
            }
    } else if(s.length > 70) {
    let mLong = (screenWidth / (1920 / 120))
        return `${s.substring(0, mLong)}…`
    } else {
        return s
    }
}