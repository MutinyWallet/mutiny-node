export default function prettyPrintAmount(n: number | bigint) {
    return n.toLocaleString().replaceAll(",", "_")
}