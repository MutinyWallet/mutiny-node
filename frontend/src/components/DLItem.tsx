export default function DLItem({ children, title }: { children: React.ReactNode, title: string }) {
    return (
        <div className="rounded border p-2 my-2">
            <>
                <dt>{title}</dt>
                <dd>{children}</dd>
            </>
        </div>
    )
}