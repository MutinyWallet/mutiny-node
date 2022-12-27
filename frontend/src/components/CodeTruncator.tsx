import takeNWidth from "@util/truncator"
import useScreenWidth from "@util/screenWidth"

type Props = {
    code: string
    truncStart?: number
  }

export default function CodeTruncator({code, truncStart}: Props) {
    const screenWidth = useScreenWidth();

    return (
        <span>{takeNWidth(code, screenWidth, truncStart)}</span>
    )
}