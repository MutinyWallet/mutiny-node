export default function takeNWidthWidth(s: string, truncStart: number, screenWidth: number): string {
    console.log(screenWidth)
    let number = truncStart / s.length
    let m = (screenWidth / number)
    let mLong = (screenWidth / (1920 / 120))
    if (s.length <= 66) {
        if (s.length > m) {
            return `${s.substring(0, m)}…`
        } else {
            return `${s.substring(0, m)}`
        }
    } else {
        return `${s.substring(0, mLong)}…`
    }
}