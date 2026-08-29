import CodeMirror from "@uiw/react-codemirror";
import { json, jsonParseLinter } from "@codemirror/lang-json";
import { linter, lintGutter } from "@codemirror/lint";
import { EditorView } from "@codemirror/view";
import { githubDark, githubLight } from "@uiw/codemirror-theme-github";
import { useMemo } from "react";

/**
 * A JSON editor for Xray outbounds and the generated config.
 *
 * CodeMirror rather than Monaco: Monaco is several megabytes, and this is
 * served over a LAN by a thin client. CodeMirror with JSON highlighting and a
 * lint gutter does everything wanted here for a fraction of the transfer.
 */
export function JsonEditor({
  value,
  onChange,
  readOnly = false,
  height = "420px",
  dark = true,
}: {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  height?: string;
  dark?: boolean;
}) {
  const extensions = useMemo(
    () => [
      json(),
      // Syntax errors are marked as you type. The server still runs
      // `xray -test` before saving — this only catches the mistakes that are
      // not worth a round trip.
      linter(jsonParseLinter()),
      lintGutter(),
      EditorView.lineWrapping,
    ],
    [],
  );

  return (
    <div
      className="overflow-hidden rounded-lg border border-border"
      style={{ height }}
    >
      <CodeMirror
        value={value}
        height={height}
        theme={dark ? githubDark : githubLight}
        extensions={extensions}
        editable={!readOnly}
        onChange={onChange}
        basicSetup={{
          lineNumbers: true,
          foldGutter: true,
          highlightActiveLine: !readOnly,
          autocompletion: false,
        }}
      />
    </div>
  );
}
