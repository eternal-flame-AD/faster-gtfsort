import { Button } from "@mui/material";
import { Link } from "react-router-dom";

function trimIndentation(input: string): string {
    let lines = input.split("\n");
    let minIndent = Infinity;
    for (let line of lines) {
        let indent = line.search(/\S/);
        if (indent !== -1) {
            minIndent = Math.min(minIndent, indent);
        }
    }
    return lines.map((line) => line.slice(minIndent)).join("\n");
}

export function formatIssueForPanic(stack?: string, message?: string) {
    let title = "[WASM] Panic in Web Worker";
    let body = trimIndentation(`# Panic in Web Worker

                \`<Description of what happened>\`

                \`<URL to input that caused the panic>\`

                <details>
                <summary>Stack Trace</summary>

                \`\`\`
                ${stack || "<no stack trace>"}
                \`\`\`

                </details>

                <details>
                <summary>Message</summary>

                \`\`\`
                ${message || "<no message>"}
                \`\`\`

                </details>

                <details>
                <summary>Environment</summary>

                \`\`\`
                UserAgent: ${navigator.userAgent}
                \`\`\`

                </details>

                `);
    return { title, body };
}

export function formatIssueForWeb(err: any) {
    let title = "[WEB] Error in Web UI";
    let body = trimIndentation(`# Error in Web UI

                \`<Description of what happened>\`

                <details>
                <summary>Stack Trace</summary>

                \`\`\`
                ${err.stack || "<no stack trace>"}
                \`\`\`

                </details>

                <details>
                <summary>Message</summary>

                \`\`\`
                ${err.message || "<no message>"}
                \`\`\`

                </details>

                <details>
                <summary>Environment</summary>

                \`\`\`
                UserAgent: ${navigator.userAgent}
                \`\`\`

                </details>

                `);
    return { title, body };
}


export function IssueLink({ repo, title, body }: { repo: string, title: string, body?: string }) {
    return (
        <Link to={`https://github.com/${repo}/issues/new?title=${encodeURIComponent(title)}&body=${encodeURIComponent(body || "")}`}>
            <Button>
                Report Issue
            </Button>
        </Link>
    )
}