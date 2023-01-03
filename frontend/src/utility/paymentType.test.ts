import { detectPaymentType, PaymentType } from "./dumb";

const INVOICE = "lntb1u1pwz5w78pp5e8w8cr5c30xzws92v36sk45znhjn098rtc4pea6ertnmvu25ng3sdpywd6hyetyvf5hgueqv3jk6meqd9h8vmmfvdjsxqrrssy29mzkzjfq27u67evzu893heqex737dhcapvcuantkztg6pnk77nrm72y7z0rs47wzc09vcnugk2ve6sr2ewvcrtqnh3yttv847qqvqpvv398"

describe("Payment type detector", () => {
    it("can detect lightning invoice", () => {
        let detected = detectPaymentType(INVOICE);
        expect(detected).toEqual(PaymentType.invoice)
    })
});