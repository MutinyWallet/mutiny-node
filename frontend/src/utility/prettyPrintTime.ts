export default function prettyPrintTime(ts: number) {
    const options = {
        weekday: 'long',
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric'
    };

    return new Date(ts * 1000).toLocaleString('en-US', options as any);
}