"""Portable evidence bundles: JSON, Markdown, HTML and SARIF 2.1.0."""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from . import __version__
from .checks import RULES
from .models import Assessment, Snapshot, digest


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def markdown(report: Assessment) -> str:
    lines = [
        "# Aegis | AWS security assessment",
        "",
        f"Snapshot: `{report.snapshot_id}`  ",
        f"Engine: `{report.engine}`  ",
        f"Completion: **{report.status}**  ",
        f"Source: **{report.source}**  ",
        f"Registered checks executed: {report.checks_completed}/{report.checks_available}  ",
        f"Evidence SHA-256: `{report.snapshot_sha256}`",
        "",
        f"{len(report.findings)} findings. {report.steps} planner steps. "
        f"{report.elapsed_seconds:.3f}s assessment time (excludes rendering).",
        "",
        "## Coverage and limitations",
        "",
        *[f"- {w}" for w in report.warnings],
        "",
    ]
    for f in report.findings:
        lines.extend(
            [
                f"## {f.rule_id} | {f.title}",
                "",
                f"**{f.severity.upper()}** · `{f.status}` · `{f.resource_id}`",
                "",
                f.description,
                "",
                "**Path:** " + " → ".join(f.path) if f.path else "",
                "",
                "**Evidence pointers in snapshot.json**",
                "",
                *[f"- `{e}`" for e in f.evidence],
                "",
                "**Remediation:** " + f.remediation,
                "",
                "**References:** " + ", ".join(f"[AWS documentation]({r})" for r in f.references),
                "",
            ]
        )
    lines.extend(
        [
            "## Reproduce",
            "",
            "Use the bundled snapshot.json with:",
            "",
            "```sh",
            "aegis replay . --out ../replayed-run",
            "```",
            "",
            "The reference engine reproduces findings without network access. LLM planning "
            "can vary; the event trace records the accepted actions for each run.",
            "",
        ]
    )
    return "\n".join(lines)


def sarif(report: Assessment) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aegis Cloud Assessment",
                        "version": __version__,
                        "rules": [
                            {"id": k, "shortDescription": {"text": v[1]}} for k, v in RULES.items()
                        ],
                    }
                },
                "invocations": [{"executionSuccessful": report.status == "completed"}],
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": "error" if f.severity in ("critical", "high") else "warning",
                        "message": {"text": f"{f.title}: {f.resource_id}. {f.description}"},
                        "partialFingerprints": {"aegisFindingKey/v1": digest(f.key)},
                        "locations": [
                            {
                                "logicalLocations": [
                                    {"fullyQualifiedName": f.resource_id, "kind": "resource"}
                                ]
                            }
                        ],
                        "properties": {
                            "status": f.status,
                            "evidence": f.evidence,
                            "remediation": f.remediation,
                            "path": f.path,
                        },
                    }
                    for f in report.findings
                ],
            }
        ],
    }


def render_html(report: Assessment) -> str:
    e = lambda value: html.escape(str(value), quote=True)  # noqa: E731
    counts = Counter(f.severity for f in report.findings)
    cards = []
    for f in report.findings:
        path = "".join(f'<span class="node">{e(p)}</span>' for p in f.path)
        evidence = "".join(f"<li><code>{e(p)}</code></li>" for p in f.evidence)
        refs = "".join(f'<a href="{e(r)}">AWS documentation ↗</a>' for r in f.references)
        cards.append(f'''<article class="finding" data-severity="{e(f.severity)}">
<div class="eyebrow"><span class="badge {e(f.severity)}">{e(f.severity)}</span>
{e(f.rule_id)} <span class="status">{e(f.status.replace("_", " "))}</span></div>
<h2>{e(f.title)}</h2><p class="resource">{e(f.resource_id)}</p><p>{e(f.description)}</p>
<div class="path">{path}</div><details><summary>Evidence &amp; remediation</summary>
<h3>Evidence in snapshot.json</h3><ul>{evidence}</ul><h3>Recommended change</h3>
<p>{e(f.remediation)}</p>{refs}</details></article>''')
    stats = "".join(
        f'<div class="metric"><strong>{counts[level]}</strong><span>{level}</span></div>'
        for level in ("critical", "high", "medium", "low")
    )
    warnings = "".join(f"<li>{e(w)}</li>" for w in report.warnings)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';
script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>Aegis · {e(report.snapshot_id)}</title><style>
:root{{color-scheme:dark;--bg:#0c1018;--panel:#141b27;--ink:#e7edf8;--muted:#9eafc7;--line:#293346;
--mint:#a4f5cd}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.65 system-ui,sans-serif}}main{{max-width:1160px;margin:auto;padding:40px 28px 80px}}
header{{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);
padding-bottom:22px}}.logo{{letter-spacing:.28em;font-size:20px;font-weight:800}}.logo b{{color:var(--mint)}}
.muted,.resource{{color:var(--muted)}}.hero{{padding:58px 0 35px;max-width:780px}}
.eyebrow{{font:12px/1.8 ui-monospace,monospace;letter-spacing:.07em;color:var(--muted)}}
h1{{font-size:clamp(34px,5vw,58px);line-height:1.08;letter-spacing:-.045em;margin:18px 0}}
h1 span{{color:var(--mint)}}h2{{font-size:21px;line-height:1.3;margin:18px 0 5px}}h3{{font-size:14px}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--line);
border-radius:14px;overflow:hidden;margin-bottom:30px}}.metric{{padding:22px 28px;background:var(--panel);
border-right:1px solid var(--line)}}.metric:last-child{{border:0}}.metric strong{{font-size:36px;
display:block;font-weight:600;line-height:1.1}}.metric span{{color:var(--muted);text-transform:capitalize}}
.layout{{display:grid;grid-template-columns:1fr 300px;gap:26px}}.finding,aside{{background:var(--panel);
border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:16px}}
aside{{align-self:start;position:sticky;top:20px;font-size:13px}}aside ul{{padding-left:18px}}
.badge{{text-transform:uppercase;border-radius:4px;padding:4px 7px;margin-right:8px;
background:#34425e;color:#d9e4ff}}.critical{{background:#4a2636;color:#ffacc3}}
.high{{background:#493b26;color:#ffd196}}.status{{float:right;font-size:10px}}p{{margin:12px 0}}
.resource,code{{font:12px/1.7 ui-monospace,monospace;overflow-wrap:anywhere}}
.path{{display:flex;flex-wrap:wrap;gap:8px}}.node{{border:1px solid #497461;color:var(--mint);
border-radius:5px;padding:5px 9px;font:12px/1.5 ui-monospace,monospace;overflow-wrap:anywhere}}
.node+.node:before{{content:'→ ';color:var(--muted)}}details{{border-top:1px solid var(--line);
padding-top:15px;margin-top:22px}}summary{{cursor:pointer;color:var(--mint)}}a{{color:var(--mint)}}
.filters{{display:flex;gap:10px;margin-bottom:20px}}input,select{{background:var(--panel);color:var(--ink);
border:1px solid var(--line);border-radius:7px;padding:12px;font:inherit}}input{{min-width:0;flex:1}}
footer{{margin-top:40px;border-top:1px solid var(--line);padding-top:18px;font-size:12px;color:var(--muted)}}
@media(max-width:780px){{.layout{{grid-template-columns:1fr}}aside{{position:static}}
.metric{{padding:16px}}main{{padding:24px 16px}}.status{{float:none;display:block;margin-top:8px}}
.hero{{padding-top:32px}}}}@media print{{body{{background:white;color:black}}.filters{{display:none}}
.layout{{display:block}}aside,.finding,.metric{{background:white;color:black;break-inside:avoid}}
details{{display:block}}summary{{display:none}}}}
</style></head><body><main><header><div class="logo"><b>◈</b> AEGIS</div>
<div class="eyebrow">CLOUD SECURITY / RESEARCH EDITION</div></header>
<section class="hero"><div class="eyebrow">{e(report.source.upper())} / {e(report.snapshot_id)}</div>
<h1>Every finding.<br><span>Backed by evidence.</span></h1>
<p class="muted">Explore configuration findings and modeled IAM paths, with reproducible
evidence and concrete remediation guidance.</p></section><div class="metrics">{stats}</div>
<div class="layout"><section><div class="filters"><input id="search" aria-label="Search findings"
placeholder="Search findings, resources, evidence…"><select id="severity" aria-label="Severity">
<option value="">All severities</option><option>critical</option><option>high</option>
<option>medium</option><option>low</option></select></div><p id="count" class="eyebrow"></p>
{"".join(cards)}<p id="empty" hidden>No findings match this view.</p></section>
<aside><div class="eyebrow">RUN MANIFEST</div><h3>{e(report.engine)} / {e(report.status)}</h3>
<p>{report.steps} steps · {report.elapsed_seconds:.3f}s</p>
<p>{report.checks_completed} / {report.checks_available} registered checks executed</p>
<p>{report.input_tokens + report.output_tokens:,} model tokens</p>
<h3>Evidence digest</h3><code>{e(report.snapshot_sha256)}</code>
<h3>Coverage &amp; limitations</h3><ul>{warnings}</ul>
<p>Modeled paths are not proof of a successful live exploit. No AWS writes are performed.</p>
<a href="report.json">Report JSON</a> · <a href="report.md">Markdown</a></aside></div>
<footer>Aegis {__version__} · Portable report · No external scripts, fonts or tracking</footer>
</main><script>
const search=document.querySelector('#search'), severity=document.querySelector('#severity');
function filter(){{let n=0; document.querySelectorAll('.finding').forEach(card=>{{
card.hidden=!(card.textContent.toLowerCase().includes(search.value.toLowerCase()) &&
(!severity.value || card.dataset.severity===severity.value));if(!card.hidden)n++;
}});document.querySelector('#count').textContent=n+' FINDINGS IN VIEW';
document.querySelector('#empty').hidden=n>0;}}
search.addEventListener('input',filter);severity.addEventListener('change',filter);filter();
</script></body></html>"""


def write_bundle(report: Assessment, snapshot: Snapshot, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "snapshot.json", snapshot.model_dump())
    write_json(output / "report.json", report.model_dump())
    write_json(output / "report.sarif", sarif(report))
    (output / "report.md").write_text(markdown(report), encoding="utf-8")
    (output / "report.html").write_text(render_html(report), encoding="utf-8")
    (output / "trace.jsonl").write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in report.trace), encoding="utf-8"
    )
