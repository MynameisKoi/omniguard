// the AI's replies: paragraphs, **bold**, headings and bullet lists, nothing else
// (used by the corner chat and the Ask AI page)
export default function AiMarkdown({ text }) {
    const inline = (s) =>
        s.split(/(\*\*[^*]+\*\*)/g).map((p, i) =>
            p.startsWith("**") && p.endsWith("**")
                ? <strong key={i}>{p.slice(2, -2)}</strong>
                : <span key={i}>{p}</span>
        );

    const blocks = [];
    let list = null;
    const flush = () => {
        if (list) { blocks.push(<ul key={`u${blocks.length}`} className="ai-list">{list}</ul>); list = null; }
    };

    text.split("\n").forEach((raw, i) => {
        const line = raw.trim();
        if (!line) { flush(); return; }
        const headingBold = /^\*\*(.+?)\*\*:?$/.exec(line);
        if (line.startsWith("#")) { flush(); blocks.push(<h4 key={i} className="ai-h">{inline(line.replace(/^#+\s*/, ""))}</h4>); return; }
        if (headingBold) { flush(); blocks.push(<h4 key={i} className="ai-h">{headingBold[1]}</h4>); return; }
        const li = /^(\d+\.|[-*])\s+(.*)$/.exec(line);
        if (li) { if (!list) list = []; list.push(<li key={i}>{inline(li[2])}</li>); return; }
        flush();
        blocks.push(<p key={i} className="ai-p">{inline(line)}</p>);
    });
    flush();
    return <div className="ai-md">{blocks}</div>;
}
