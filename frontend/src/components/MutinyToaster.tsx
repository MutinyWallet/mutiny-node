import toast, { Toaster, resolveValue } from "react-hot-toast"

export default function MutinyToaster() {
    return (
        <Toaster position='top-center' toastOptions={{ duration: 2000 }} gutter={8}>
            {(t) => (
                <div
                    className={`bg-[#EEE] border-r-[#DDD] border-b-[#999] border-l-[#999] border-t-[#DDD] border-4 text-black text-xl font-light shadow-lg p-4 my-4; ${t.visible ? 'animate-enter' : 'animate-leave'
                        }`}
                >
                    {resolveValue(t.message, t)}
                </div>
            )}
        </Toaster>
    )
}