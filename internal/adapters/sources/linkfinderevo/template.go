package linkfinderevo

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>GoLinkfinderEVO findings</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; background: #0b0c10; color: #f0f3f6; }
        h1 { margin-bottom: 0.5rem; }
        .summary { margin-bottom: 2rem; }
        .resource { margin-bottom: 2rem; padding: 1.25rem; background: #1f2833; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .resource-title { display: flex; justify-content: space-between; align-items: baseline; }
        .resource-title a { color: #66fcf1; text-decoration: none; word-break: break-all; }
        .badge { background: #45a29e; padding: 0.25rem 0.75rem; border-radius: 999px; color: #0b0c10; font-weight: bold; }
        ul { list-style: none; padding-left: 0; margin: 1rem 0 0 0; }
        li { margin-bottom: 1rem; padding: 0.75rem; background: #0b0c10; border-radius: 6px; }
        .endpoint-header { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: baseline; }
        .endpoint-header a { color: #c5c6c7; text-decoration: none; word-break: break-all; }
        .endpoint-index { background: #45a29e; color: #0b0c10; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.85rem; font-weight: bold; }
        .endpoint-line { font-size: 0.85rem; color: #66fcf1; }
        pre { background: #0b0c10; color: #f0f3f6; padding: 0.75rem; border-radius: 4px; overflow-x: auto; margin: 0.5rem 0 0; }
    </style>
</head>
<body>
    <h1>GoLinkfinderEVO findings</h1>
    <div class="summary">
        <p>Generated at: {{.GeneratedAt}}</p>
        <p>Total resources: {{.TotalResources}}</p>
        <p>Total endpoints: {{.TotalEndpoints}}</p>
    </div>
    {{range .Resources}}
    <section class="resource">
        <div class="resource-title">
            <a href="{{.Name}}" target="_blank" rel="nofollow noopener noreferrer">{{.Name}}</a>
            <span class="badge">{{.Count}} endpoint{{if ne .Count 1}}s{{end}}</span>
        </div>
        {{if .Endpoints}}
        <ul>
            {{range .Endpoints}}
            <li>
                <div class="endpoint-header">
                    <span class="endpoint-index">#{{.Index}}</span>
                    <a href="{{.Link}}" target="_blank" rel="nofollow noopener noreferrer">{{.Link}}</a>
                    {{if gt .Line 0}}<span class="endpoint-line">Line {{.Line}}</span>{{end}}
                </div>
                {{if .Context}}
                <pre><code>{{.Context}}</code></pre>
                {{end}}
            </li>
            {{end}}
        </ul>
        {{else}}
        <p>No endpoints were found.</p>
        {{end}}
    </section>
    {{end}}
</body>
</html>
`
