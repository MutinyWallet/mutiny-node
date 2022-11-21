export default function prettyPrintAmount(n: number | bigint) {
    return n.toLocaleString().replace(",", "_")
}