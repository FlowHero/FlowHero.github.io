/**
 * Renders a string from content.ts, turning `**phrase**` into a highlighted
 * <strong>. The previous site kept that emphasis as raw HTML in its
 * translations; this keeps it without ever setting innerHTML.
 */
export default function Rich({ text, strongClassName = 'font-semibold text-signal-glow' }: { text: string; strongClassName?: string }) {
  const parts = text.split(/\*\*(.+?)\*\*/g);
  return (
    <>
      {parts.map((part, i) =>
        // split() with a capture group alternates plain text and captures, so
        // every odd index is a phrase that sat between the asterisks.
        i % 2 === 1 ? (
          <strong key={i} className={strongClassName}>
            {part}
          </strong>
        ) : (
          part
        )
      )}
    </>
  );
}
