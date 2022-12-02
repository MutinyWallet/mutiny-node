export default function SimpleText({ children }: React.ComponentPropsWithoutRef<"p">) {
    return <p className="text-2xl font-light">{children}</p>
}