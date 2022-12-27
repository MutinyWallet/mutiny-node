export default function takeNWidthWidth(s: string, screenWidth: number, truncStart?: number): string {
    // code walkthrough 
     /* 
    truncStart is ~width in screensize where you want the string to begin truncating
    Works best with font-size ~1em
    Strings longer than 70 characters will automatically be truncated to the screensize
    */
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