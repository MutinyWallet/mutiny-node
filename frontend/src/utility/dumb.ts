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

export function detectPaymentType(p: string): PaymentType {
    if (p.startsWith("lnt")) {
        return PaymentType.invoice
    } else if (p.startsWith("03") || p.startsWith("02")) {
        return PaymentType.keysend
    } else if (p.startsWith("tb1")) {
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
