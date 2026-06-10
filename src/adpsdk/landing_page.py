"""ADP SDK — Agent Landing Page HTML generator.

Generates a dark-themed, ADP-compliant HTML landing page with:
- Embedded JSON-LD script tag with full agent metadata
- Capability cards
- Endpoint list
- Agent relationships
- Code snippets for SDK integration
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any


def generate_landing_page(agent_json: dict[str, Any]) -> str:
    """Generate an ADP-compliant HTML landing page for an agent.

    Args:
        agent_json: Full agent.json metadata dict.

    Returns:
        HTML document string.
    """
    identity = agent_json.get("identity", {})
    capabilities = agent_json.get("capabilities", [])
    endpoints = agent_json.get("endpoints", {})
    relationships = agent_json.get("relationships", [])

    styles = _get_styles()

    cap_cards = "\n".join(
        _capability_card(c) for c in capabilities
    )

    peer_list = _relationship_list(relationships)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="agent-id" content="{_esc(identity.get("id", ""))}">
  <meta name="agent-protocol" content="ADP/1.0">
  <meta name="agent-fingerprint" content="{_esc(identity.get("publicKey", {}).get("fingerprint", ""))}">
  <title>{_esc(identity.get("name", "Agent"))} — {_esc(identity.get("id", ""))}</title>
  <script type="application/ld+json">
{json.dumps(agent_json, indent=2)}
  </script>
  {styles}
</head>
<body>
  <div class="container">
    <header>
      <div class="status-dot online"></div>
      <h1>{_esc(identity.get("name", "Agent"))}</h1>
      <p class="agent-id">{_esc(identity.get("id", ""))}</p>
      <p class="owner">by {_esc(identity.get("owner", "Unknown"))}</p>
    </header>

    <section class="card">
      <h2>🔑 Identity</h2>
      <table class="info-table">
        <tr><td>Protocol</td><td>ADP/1.0</td></tr>
        <tr><td>Key Algorithm</td><td>Ed25519</td></tr>
        <tr><td>Fingerprint</td><td><code>{_esc(identity.get("publicKey", {}).get("fingerprint", ""))}</code></td></tr>
      </table>
    </section>

    <section class="card">
      <h2>🎯 Capabilities</h2>
      <div class="capabilities">
        {cap_cards}
      </div>
    </section>

    <section class="card">
      <h2>🔗 Endpoints</h2>
      <div class="endpoint-list">
        {_endpoint_rows(endpoints)}
      </div>
    </section>

    <section class="card">
      <h2>🤝 Relationships</h2>
      <ul>{peer_list}</ul>
    </section>

    <section class="card connect-section">
      <h2>🚀 Connect to this Agent</h2>
      <p>Use the ADP SDK to connect:</p>
      <pre><code>import asyncio
from adpsdk import discover_agent
import dns.resolver

async def main():
    agent = await discover_agent(
        "{_esc(identity.get("domain", ""))}",
        dns_resolve_txt=my_dns_resolver,
    )
    print(f"Trust level: {{agent.trust_level}}")

asyncio.run(main())</code></pre>
      <p>Or connect directly via WebSocket:</p>
      <pre><code>{_esc(endpoints.get("chat", ""))}</code></pre>
    </section>

    <footer>
      <p>Powered by <strong>ADP (Agent Discovery Protocol) v1.0</strong></p>
      <p>Generated at {datetime.now(timezone.utc).isoformat()}</p>
    </footer>
  </div>
</body>
</html>"""


def _esc(s: str) -> str:
    """HTML-escape a string."""
    if not s:
        return ""
    return html.escape(s, quote=True)


def _capability_card(cap: dict[str, Any]) -> str:
    """Render a single capability card."""
    name = _esc(cap.get("name", "Unknown"))
    desc = _esc(cap.get("description", ""))
    inputs = ", ".join(cap.get("input", []))
    outputs = ", ".join(cap.get("output", []))
    pricing = cap.get("pricing", {}).get("model", "free")
    price_html = ""
    if pricing != "free":
        price_html = f'<span class="tag price">💰 {pricing}</span>'
    return f"""    <div class="capability-card">
      <h3>{name}</h3>
      <p>{desc}</p>
      <div class="cap-tags">
        <span class="tag input">📥 {inputs}</span>
        <span class="tag output">📤 {outputs}</span>
        {price_html}
      </div>
    </div>"""


def _relationship_list(rels: list[dict[str, Any]]) -> str:
    """Render a list of agent relationships."""
    if not rels:
        return "<li>No peers yet</li>"
    items = []
    for r in rels:
        typ = _esc(r.get("type", ""))
        name = _esc(r.get("name", ""))
        rid = _esc(r.get("id", ""))
        trust = r.get("trust", "")
        trust_str = f" — {trust}" if trust else ""
        items.append(f"<li>🤝 {name} ({typ}: {rid}){trust_str}</li>")
    return "\n".join(items)


def _endpoint_rows(endpoints: dict[str, str]) -> str:
    """Render endpoint rows."""
    rows = []
    for name, url in endpoints.items():
        rows.append(
            f'        <div class="endpoint">'
            f'<span class="endpoint-name">{_esc(name)}</span>'
            f'<code>{_esc(url)}</code>'
            f'</div>'
        )
    return "\n".join(rows)


def _get_styles() -> str:
    """Get the CSS styles for the landing page (dark theme)."""
    return """<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0d1117; color: #c9d1d9;
      line-height: 1.6;
    }
    .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
    header { text-align: center; margin-bottom: 40px; }
    .status-dot {
      width: 12px; height: 12px; border-radius: 50%; margin: 0 auto 12px;
    }
    .status-dot.online { background: #3fb950; box-shadow: 0 0 8px rgba(63,185,80,0.5); }
    .status-dot.offline { background: #f85149; box-shadow: 0 0 8px rgba(248,81,73,0.5); }
    .status-dot.degraded { background: #d29922; box-shadow: 0 0 8px rgba(210,153,34,0.5); }
    h1 { font-size: 32px; color: #f0f6fc; margin-bottom: 4px; }
    .agent-id { color: #58a6ff; font-size: 14px; margin-bottom: 4px; }
    .owner { color: #8b949e; font-size: 14px; }
    .card {
      background: #161b22; border: 1px solid #30363d;
      border-radius: 8px; padding: 24px; margin-bottom: 20px;
    }
    .card h2 { font-size: 18px; color: #f0f6fc; margin-bottom: 16px; }
    .info-table { width: 100%; border-collapse: collapse; }
    .info-table td { padding: 8px 12px; border-bottom: 1px solid #21262d; }
    .info-table td:first-child { color: #8b949e; width: 150px; }
    .info-table code { color: #58a6ff; font-size: 12px; }
    .capabilities { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 16px; }
    .capability-card {
      background: #0d1117; border: 1px solid #30363d;
      border-radius: 6px; padding: 16px;
    }
    .capability-card h3 { color: #f0f6fc; margin-bottom: 8px; font-size: 16px; }
    .capability-card p { color: #8b949e; font-size: 13px; margin-bottom: 12px; }
    .cap-tags { display: flex; flex-wrap: wrap; gap: 6px; }
    .tag { font-size: 11px; padding: 2px 8px; border-radius: 12px; background: #21262d; color: #8b949e; }
    .tag.price { background: #1a3a2a; color: #3fb950; }
    .endpoint-list { display: flex; flex-direction: column; gap: 12px; }
    .endpoint { display: flex; align-items: center; gap: 16px; }
    .endpoint-name {
      font-size: 13px; color: #8b949e; min-width: 80px; text-transform: uppercase;
    }
    .endpoint code { color: #58a6ff; font-size: 13px; word-break: break-all; }
    ul { list-style: none; }
    li { padding: 6px 0; color: #8b949e; font-size: 14px; }
    .connect-section p { color: #8b949e; margin-bottom: 12px; }
    pre {
      background: #0d1117; border: 1px solid #30363d;
      border-radius: 6px; padding: 12px; overflow-x: auto;
      margin-bottom: 12px;
    }
    pre code { color: #c9d1d9; font-size: 13px; }
    footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #21262d; color: #484f58; font-size: 13px; }
  </style>"""
