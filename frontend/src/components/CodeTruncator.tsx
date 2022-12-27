import takeNWidth from "@util/takeNWidth"
import useScreenWidth from "@util/screenWidth"

type Props = {
    code: string
    truncStart?: number
  }

export default function CodeTruncator({code, truncStart}: Props) {
    const screenWidth = useScreenWidth();
    /* 
    truncStart is ~width in screensize where you want the string to begin truncating
    Works best with font-size ~1em
    Strings longer than 70 characters will automatically be truncated to the screensize
    */

    return (
        <span>{takeNWidth(code, screenWidth, truncStart)}</span>
    )
}