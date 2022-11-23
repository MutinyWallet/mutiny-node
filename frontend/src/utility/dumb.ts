// Stuff I'll probably delete when I do it "right"

import { NodeManager } from "node-manager";
import toast from "react-hot-toast";
export async function getFirstNode(nodeManager: NodeManager): Promise<string> {
    const myNodes = await nodeManager?.list_nodes();
    console.log(myNodes);
    const myNode = myNodes[0] as string

    if (!myNode) {
        throw new Error("We don't have a node set up yet!")
    }

    return myNode
}

export enum PaymentType {
    "invoice",
    "keysend",
    "onchain",
    "unknown"
}

// TODO: use a real library for this or at least try harder
// https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
// https://en.bitcoin.it/wiki/List_of_address_prefixes
export function detectPaymentType(p: string): PaymentType {
    if (p.startsWith("lntb") || p.startsWith("lnbcrt") || p.startsWith("lnbc")) {
        return PaymentType.invoice
    } else if (p.startsWith("03") || p.startsWith("02")) {
        return PaymentType.keysend
    } else if (p.startsWith("tb1") || p.startsWith("bc1") || p.startsWith("bcrt1") || p.startsWith("1") || p.startsWith("3") || p.startsWith("2") || p.startsWith("m") || p.startsWith("n")) {
        return PaymentType.onchain
    } else {
        return PaymentType.unknown
    }
}

export function toastAnything(e: unknown) {
    if (e instanceof Error) {
        toast(e.message)
    } else if (typeof e === "string") {
        toast(e as string)
    } else {
        toast(`Weird error! ${e}`)
    }
}

export function mempoolTxUrl(txid?: string, network?: string) {
    if (!txid || !network) {
        console.error("Problem creating the mempool url")
        return "#"
    }

    return `https://mempool.space/${network === "testnet" ? "testnet" : ""}/tx/${txid}`
}