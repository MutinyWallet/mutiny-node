import takeNWidth from "@util/takeNWidth"
import useScreenWidth from "@util/screenWidth"

type Props = {
    code: string
    truncStart?: number
  }

export default function CodeTruncator({code, truncStart}: Props) {
    const screenWidth = useScreenWidth();
    // the percent is when the width of the screen is 

    return (
        <span>{takeNWidth(code, screenWidth, truncStart)}</span>
    )
}