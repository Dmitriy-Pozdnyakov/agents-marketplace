"""Refresh the offline documentation embedded in marketplace-preview.html."""

import json
import os
import stat
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREVIEW = ROOT / "marketplace-preview.html"
DOCUMENTS = (
    "README.md",
    "openapi.yaml",
    "agents/team-assistant.md",
    "agents/chat-task-agent.md",
    "agents/sre-grafana.md",
    "examples/agent-offering.yaml",
    "examples/chat-task-agent-offering.yaml",
    "examples/sre-grafana-offering.yaml",
    "architecture.md",
    "agents/TEMPLATE.md",
)
START = '<template id="embedded-document-store">\n<pre id="embedded-document-data">'
END = "</pre>\n</template>"


def main():
    documents = {name: (ROOT / name).read_text(encoding="utf-8") for name in DOCUMENTS}
    data = json.dumps(documents, ensure_ascii=False, separators=(",", ":"))
    escapes = {ord(char): f"\\u{ord(char):04x}" for char in "<>&\u2028\u2029"}
    html = PREVIEW.read_text(encoding="utf-8")
    if html.count(START) != 1:
        raise SystemExit("Expected one embedded-document-store in the HTML preview.")
    before, _, tail = html.partition(START)
    _, marker, after = tail.partition(END)
    if not marker:
        raise SystemExit("Embedded document block is incomplete.")
    updated = before + START + data.translate(escapes) + END + after
    if updated == html:
        return

    with tempfile.NamedTemporaryFile(dir=PREVIEW.parent, delete=False) as temp:
        target = Path(temp.name)
    try:
        target.write_text(updated, encoding="utf-8")
        target.chmod(stat.S_IMODE(PREVIEW.stat().st_mode))
        if PREVIEW.read_text(encoding="utf-8") != html:
            raise SystemExit("The preview was edited during the update. Run this command again.")
        os.replace(target, PREVIEW)
    finally:
        target.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
