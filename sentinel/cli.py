"""Unified command line interface for LLMSentinel."""

# mypy: disable-error-code=untyped-decorator

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from sentinel.gateway.approvals import ApprovalVerifier, issue_approval_token
from sentinel.gateway.auth import AuthContext
from sentinel.gateway.pipeline import SecurityPipeline
from sentinel.gateway.policy import (
    DEFAULT_POLICY_PATH,
    load_policy,
    verify_policy_signature,
    write_policy_signature,
)
from sentinel.redteam.attacks import ATTACKS, Attack, mutations
from sentinel.reporting.formats import json_report, markdown_report, sarif_report, write_report
from sentinel.reporting.pdf import pdf_report
from sentinel.scanner.model_artifacts import scan_model_path
from sentinel.scanner.source import scan_path

app = typer.Typer(help="Zero-trust AI security operations CLI", no_args_is_help=True, pretty_exceptions_show_locals=False)
policy_app = typer.Typer(help="Validate and sign policy artifacts", no_args_is_help=True)
app.add_typer(policy_app, name="policy")
console = Console()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        return None


@dataclass(frozen=True)
class ProbeOutcome:
    disposition: str
    canary_exposed: bool
    redacted: bool
    response_excerpt: str


@policy_app.command("validate")
def policy_validate(path: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Validate policy structure and required detached signature."""
    loaded = load_policy(path)
    console.print(f"[green]Policy valid[/green] · {loaded.get('name', path.name)} · schema v{loaded['version']} · revision {loaded.get('revision', '1')}")


@policy_app.command("sign")
def policy_sign(
    path: Path = typer.Argument(..., exists=True, readable=True),
    key_env: str = typer.Option("SENTINEL_POLICY_SIGNING_KEY", "--key-env", help="Environment variable containing the signing key"),
    key_id: str = typer.Option("default", "--key-id", help="Non-secret signing key identifier"),
) -> None:
    """Sign a validated policy with its configured detached signature algorithm."""
    secret = os.getenv(key_env)
    if not secret:
        raise typer.BadParameter(f"Set {key_env} in the environment or a secret manager")
    loaded = load_policy(path, verify_signature=False)
    sidecar = write_policy_signature(path, loaded, secret, key_id)
    console.print(f"[green]Signed policy[/green] · {sidecar}")


@policy_app.command("verify")
def policy_verify(path: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Verify a signed policy sidecar using its configured environment key."""
    loaded = load_policy(path, verify_signature=False)
    integrity = loaded.get("integrity", {})
    key_env = str(integrity.get("verification_key_env", integrity.get("signature_env", "SENTINEL_POLICY_SIGNING_KEY")))
    key = os.getenv(key_env)
    if not key:
        raise typer.BadParameter(f"Set {key_env} in the environment or a secret manager")
    valid, reason = verify_policy_signature(path, loaded, key)
    if not valid:
        console.print(f"[red]Policy signature invalid[/red] · {reason}")
        raise typer.Exit(code=1)
    console.print(f"[green]Policy signature verified[/green] · {loaded.get('name', path.name)}")


@policy_app.command("keygen")
def policy_keygen(
    private_output: Path = typer.Option(Path(".sentinel/policy-signing.key.b64"), "--private-output"),
    public_output: Path = typer.Option(Path(".sentinel/policy-verify.key.b64"), "--public-output"),
    force: bool = typer.Option(False, "--force", help="Replace existing key files"),
) -> None:
    """Generate a raw Ed25519 key pair for policy signing and verification."""
    if not force and (private_output.exists() or public_output.exists()):
        raise typer.BadParameter("A key output already exists; pass --force only when rotating the key")
    try:
        import base64

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise typer.BadParameter("Install LLMSentinel with the 'enterprise' extra to generate Ed25519 keys") from exc
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_output.parent.mkdir(parents=True, exist_ok=True)
    public_output.parent.mkdir(parents=True, exist_ok=True)
    private_output.write_text(base64.b64encode(private_bytes).decode("ascii") + "\n", encoding="ascii")
    public_output.write_text(base64.b64encode(public_bytes).decode("ascii") + "\n", encoding="ascii")
    try:
        private_output.chmod(0o600)
        public_output.chmod(0o644)
    except OSError:
        pass
    console.print(f"Created private key: {private_output} [red](protect this file)[/red]")
    console.print(f"Created public verification key: {public_output}")


def _probe_disposition(status_code: int, result: object) -> str:
    if status_code == 401:
        return "auth_rejected"
    if status_code == 429:
        return "rate_limited"
    if status_code == 403 and isinstance(result, dict):
        detail = result.get("detail")
        if isinstance(detail, dict) and isinstance(detail.get("decision"), dict):
            decision = detail["decision"]
            if decision.get("allowed") is False and decision.get("layer") in {"L1", "L2"}:
                return "policy_blocked"
    if status_code == 403:
        return "denied_unclassified"
    if status_code >= 500:
        return "upstream_error"
    if 300 <= status_code < 400:
        return "redirected"
    if status_code >= 400:
        return "request_rejected"
    return "allowed"


@app.command()
def init(
    path: Path = typer.Option(Path("sentinel-policy.yaml"), "--path", "-p", help="Destination policy file"),
    force: bool = typer.Option(False, "--force", help="Replace an existing policy file"),
) -> None:
    """Create a starter policy file."""
    if path.exists() and not force:
        raise typer.BadParameter(f"{path} already exists; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    console.print(f"[green]Created policy:[/green] {path}")


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, readable=True, help="Source file, model artifact, or directory"),
    format: str = typer.Option("json", "--format", help="json, sarif, markdown, or pdf"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to this path"),
    fail_on: str = typer.Option("none", "--fail-on", help="Exit 1 when findings reach this severity: none, low, medium, high, critical"),
) -> None:
    """Scan Python source and supported model artifacts without executing them."""
    findings = scan_path(target) + scan_model_path(target)
    selected = format.lower()
    severity_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = fail_on.lower()
    if threshold not in severity_order:
        raise typer.BadParameter("fail-on must be none, low, medium, high, or critical")

    def enforce_threshold() -> None:
        rank = severity_order[threshold]
        if rank and any(severity_order.get(item.severity.lower(), 0) >= rank for item in findings):
            raise typer.Exit(code=1)

    if format.lower() == "pdf":
        if not output:
            raise typer.BadParameter("PDF output requires --output <file.pdf>")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(pdf_report(findings))
        console.print(f"Wrote executive PDF with {len(findings)} finding(s) to {output}")
        enforce_threshold()
        return
    renderers = {"json": json_report, "sarif": sarif_report, "markdown": markdown_report, "md": markdown_report}
    if selected not in renderers:
        raise typer.BadParameter("format must be json, sarif, or markdown")
    content = renderers[selected](findings)
    if output:
        write_report(content, output)
        console.print(f"Wrote {len(findings)} finding(s) to {output}")
    else:
        console.print(content)
    enforce_threshold()


@app.command()
def gateway(
    upstream: str | None = typer.Option(None, "--upstream", help="OpenAI-compatible chat completions URL"),
    policy: Path = typer.Option(Path(DEFAULT_POLICY_PATH), "--policy", help="Policy YAML"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
    allow_unauthenticated_network: bool = typer.Option(False, "--allow-unauthenticated-network", help="Allow a non-loopback bind with the local unauthenticated policy; use only on a trusted isolated network"),
) -> None:
    """Run the policy-enforcing gateway (local mock by default)."""
    from sentinel.gateway.app import create_app

    loaded_policy = load_policy(policy)
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if not loopback and not loaded_policy.get("auth", {}).get("require_auth", False) and not allow_unauthenticated_network:
        raise typer.BadParameter("non-loopback binds require auth.require_auth=true or explicit --allow-unauthenticated-network")
    os.environ["SENTINEL_POLICY"] = str(policy)
    if upstream:
        os.environ["SENTINEL_UPSTREAM_URL"] = upstream
    console.print(f"[cyan]LLMSentinel gateway[/cyan] http://{host}:{port} · policy {policy}")
    uvicorn.run(create_app(str(policy), upstream), host=host, port=port)


@app.command()
def sandbox(host: str = typer.Option("127.0.0.1", "--host"), port: int = typer.Option(8001, "--port", min=1, max=65535)) -> None:
    """Run the intentionally vulnerable local demo target."""
    from sentinel.sandbox.app import app as sandbox_app

    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if not loopback:
        raise typer.BadParameter("the intentionally vulnerable sandbox can only bind to loopback")
    console.print(f"[yellow]Vulnerable demo sandbox[/yellow] http://{host}:{port} — keep local")
    uvicorn.run(sandbox_app, host=host, port=port)


def _send_probe(target: str, payload: str, token: str | None = None, timeout: float = 8.0) -> ProbeOutcome:
    body = json.dumps({"model": "sentinel-redteam", "messages": [{"role": "user", "content": payload}]}).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(target.rstrip("/") + "/v1/chat/completions", body, headers, method="POST")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                leaked = b"CANARY_SECRET_9941_ALPHA" in raw
                return ProbeOutcome("response_error", leaked, False, "target response exceeds 1 MiB")
            result = json.loads(raw.decode("utf-8", errors="replace"))
        text = json.dumps(result)
        sentinel = result.get("sentinel") if isinstance(result, dict) else None
        redactions = (
            isinstance(sentinel, dict)
            and isinstance(sentinel.get("redactions"), list)
            and bool(sentinel["redactions"])
            and "[REDACTED:" in text
        )
        disposition = _probe_disposition(response.status, result)
        return ProbeOutcome(disposition, "CANARY_SECRET_9941_ALPHA" in text, redactions, text[:500])
    except urllib.error.HTTPError as exc:
        raw = exc.read(1_000_001)
        full_text = raw.decode("utf-8", errors="replace")
        try:
            result = json.loads(full_text)
        except json.JSONDecodeError:
            result = None
        disposition = _probe_disposition(exc.code, result)
        text = full_text[:500]
        return ProbeOutcome(disposition, "CANARY_SECRET_9941_ALPHA" in full_text, False, text)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return ProbeOutcome("request_error", False, False, f"{type(exc).__name__}: {exc}")


@app.command()
def redteam(
    target: str = typer.Option(..., "--target", help="Authorized target base URL"),
    mode: str = typer.Option("standard", "--mode", help="standard or adaptive"),
    token: str | None = typer.Option(None, "--token", envvar="SENTINEL_REDTEAM_TOKEN", hide_input=True, help="Bearer token for an authenticated target"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write transcript as JSON"),
) -> None:
    """Run a bounded prompt-injection suite against the explicitly supplied target."""
    if mode not in {"standard", "adaptive"}:
        raise typer.BadParameter("mode must be standard or adaptive")
    parsed_target = urlsplit(target)
    if parsed_target.scheme not in {"http", "https"} or not parsed_target.hostname or parsed_target.username or parsed_target.password or parsed_target.fragment or parsed_target.query:
        raise typer.BadParameter("target must be an http(s) base URL without embedded credentials or fragments")
    if token and parsed_target.scheme != "https":
        try:
            local_target = ipaddress.ip_address(parsed_target.hostname).is_loopback
        except ValueError:
            local_target = parsed_target.hostname.lower() == "localhost"
        if not local_target:
            raise typer.BadParameter("bearer tokens require HTTPS except for loopback development targets")
    rows: list[dict[str, object]] = []
    for attack in ATTACKS:
        probes = [attack.payload]
        if mode == "adaptive":
            probes.extend(mutations(attack.payload))
        canary = False
        sanitized = False
        outcomes: list[ProbeOutcome] = []
        for probe in probes:
            outcome = _send_probe(target, probe, token)
            outcomes.append(outcome)
            canary |= outcome.canary_exposed
            sanitized |= outcome.redacted
            # Stop after a confirmed canary disclosure; otherwise exercise the bounded variants.
            if outcome.canary_exposed:
                break
        dispositions = [outcome.disposition for outcome in outcomes]
        all_blocked = bool(dispositions) and all(item == "policy_blocked" for item in dispositions)
        all_mitigated = bool(dispositions) and all(
            item == "policy_blocked" or outcome.redacted
            for item, outcome in zip(dispositions, outcomes, strict=True)
        )
        if canary:
            status = "CRITICAL: CANARY EXPOSED"
        elif all_blocked:
            status = "POLICY BLOCKED"
        elif all_mitigated:
            status = "OUTPUT SANITIZED"
        elif all(item == "auth_rejected" for item in dispositions):
            status = "AUTH REJECTED"
        elif all(item == "rate_limited" for item in dispositions):
            status = "RATE LIMITED"
        elif any(item in {"request_error", "response_error", "upstream_error"} for item in dispositions):
            status = "TARGET ERROR"
        elif any(item in {"denied_unclassified", "request_rejected", "redirected"} for item in dispositions):
            status = "DENIED (UNCLASSIFIED)"
        else:
            status = "NOT MITIGATED"
        rows.append({"id": attack.id, "category": attack.category, "status": status, "blocked": all_blocked, "mitigated": all_mitigated, "dispositions": dispositions, "output_sanitized": sanitized, "canary_exposed": canary, "attempts": len(outcomes), "transcript": [outcome.response_excerpt for outcome in outcomes]})
    table = Table(title=f"LLMSentinel red-team · {target} · {mode}")
    for column in ("Attack", "Category", "Result", "Tries"):
        table.add_column(column)
    for row in rows:
        result = str(row["status"])
        style = "green" if result in {"POLICY BLOCKED", "OUTPUT SANITIZED"} else "yellow" if result in {"AUTH REJECTED", "RATE LIMITED"} else "red"
        table.add_row(str(row["id"]), str(row["category"]), f"[{style}]{result}[/{style}]", str(row["attempts"]))
    console.print(table)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"target": target, "mode": mode, "results": rows}, indent=2), encoding="utf-8")
        console.print(f"Transcript written to {output}")
    if any(row["canary_exposed"] or not row["mitigated"] for row in rows):
        raise typer.Exit(code=1)


@app.command()
def demo() -> None:
    """Exercise the vulnerable sandbox and real gateway app through local HTTP clients."""
    import httpx

    from sentinel.gateway.app import create_app
    from sentinel.sandbox.app import CANARY_SECRET
    from sentinel.sandbox.app import app as sandbox_app

    table = Table(title="LLMSentinel v3.0 · local security demo")
    table.add_column("Attack", style="cyan")
    table.add_column("Vulnerable sandbox")
    table.add_column("Gateway")
    blocked_count = 0
    leaked_count = 0
    results: list[dict[str, object]] = []
    sanitized_count = 0
    with tempfile.TemporaryDirectory(prefix="llmsentinel-demo-") as temporary_directory:
        gateway_app = create_app(audit_path=str(Path(temporary_directory) / "audit.jsonl"))
        async def run_probes() -> list[tuple[Attack, str, int, str]]:
            probes = []
            sandbox_transport = httpx.ASGITransport(app=sandbox_app)
            gateway_transport = httpx.ASGITransport(app=gateway_app)
            async with httpx.AsyncClient(transport=sandbox_transport, base_url="http://sandbox") as sandbox_client:
                async with httpx.AsyncClient(transport=gateway_transport, base_url="http://gateway") as gateway_client:
                    for attack in ATTACKS:
                        body = {"model": "sentinel-demo", "messages": [{"role": "user", "content": attack.payload}]}
                        vulnerable_response = await sandbox_client.post("/v1/chat/completions", json=body)
                        protected_response = await gateway_client.post("/v1/chat/completions", json=body)
                        probes.append((attack, vulnerable_response.text, protected_response.status_code, protected_response.text))
            return probes

        for attack, vulnerable_text, protected_status, protected in asyncio.run(run_probes()):
            leaked = CANARY_SECRET in vulnerable_text
            blocked = protected_status == 403
            sanitized = "active_html" in protected or "[REDACTED:" in protected
            try:
                response = json.loads(protected)
            except json.JSONDecodeError:
                response = {}
            decision = response.get("detail", {}) if blocked else response.get("sentinel", {})
            leaked_count += int(leaked)
            blocked_count += int(blocked)
            sanitized_count += int(sanitized)
            gateway_status = "[green]BLOCKED[/green]" if blocked else "[green]SANITIZED[/green]" if sanitized else "[yellow]ALLOWED[/yellow]"
            table.add_row(attack.id, "[red]CANARY LEAKED[/red]" if leaked else "no canary", gateway_status)
            results.append({"id": attack.id, "category": attack.category, "vulnerable_canary_exposed": leaked, "gateway_blocked": blocked, "gateway_output_sanitized": sanitized, "decision": decision})
    console.print(table)
    summary = Table(title="Run summary")
    summary.add_column("Measure")
    summary.add_column("Result", justify="right")
    summary.add_row("Deterministic probes", str(len(ATTACKS)))
    summary.add_row("Sandbox canary exposures", str(leaked_count))
    summary.add_row("Gateway blocks", str(blocked_count))
    summary.add_row("Gateway output sanitizations", str(sanitized_count))
    console.print(summary)
    report = Path("reports/demo-report.md")
    report.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# LLMSentinel local demo", "", f"- Date: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}", f"- Attacks: {len(ATTACKS)}", f"- Vulnerable canary exposures: {leaked_count}", f"- Gateway blocks: {blocked_count}", f"- Gateway output sanitizations: {sanitized_count}", "", "| Attack | Sandbox exposed canary | Gateway blocked | Output sanitized |", "|---|---:|---:|---:|"]
    lines += [f"| {item['id']} | {item['vulnerable_canary_exposed']} | {item['gateway_blocked']} | {item['gateway_output_sanitized']} |" for item in results]
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"Report: {report}")


@app.command()
def verify(policy: Path = typer.Option(Path(DEFAULT_POLICY_PATH), "--policy")) -> None:
    """Check built-in deterministic security invariants without external APIs."""
    approval_secret = "llmsentinel-local-verification-key-not-for-deployment"
    auth = AuthContext("verify-tenant", "user")
    admin = AuthContext("verify-tenant", "admin", "verify-subject", authenticated=True)
    pipeline = SecurityPipeline(load_policy(policy), ApprovalVerifier(approval_secret))
    assertions = []
    for attack in ATTACKS:
        if attack.expected == "sanitize":
            clean, redactions = pipeline.sanitize_output(attack.payload)
            assertions.append((attack.id, clean != attack.payload and bool(redactions)))
        elif "TOOL" not in attack.id and "PATH" not in attack.id:
            assertions.append((attack.id, not pipeline.inspect_input(attack.payload, auth).allowed))
    approval = issue_approval_token(admin, "delete_user", {"user_id": "u-1"}, approval_secret)
    assertions += [
        ("tool-not-allowlisted", not pipeline.inspect_tool("delete_everything", {}, auth).allowed),
        ("critical-tool-denied-for-user", not pipeline.inspect_tool("delete_user", {"user_id": "u-1"}, auth, "approval").allowed),
        ("critical-tool-requires-approval", pipeline.inspect_tool("delete_user", {"user_id": "u-1"}, admin).reason == "human_approval_required"),
        ("critical-tool-requires-authentication", pipeline.inspect_tool("delete_user", {"user_id": "u-1"}, AuthContext("verify-tenant", "admin")).reason == "authentication_required_for_critical_tool"),
        ("tool-argument-path-traversal", not pipeline.inspect_tool("read_profile", {"user_id": "../etc/passwd"}, auth).allowed),
        ("tool-schema-required-field", pipeline.inspect_tool("search_documents", {}, auth).reason == "tool_argument_schema_violation"),
        ("critical-tool-allowed-with-approval", pipeline.inspect_tool("delete_user", {"user_id": "u-1"}, admin, approval).allowed),
        ("critical-tool-approval-is-action-bound", pipeline.inspect_tool("delete_user", {"user_id": "u-2"}, admin, approval).reason == "approval_token_action_mismatch"),
        ("critical-tool-approval-is-single-use", pipeline.inspect_tool("delete_user", {"user_id": "u-1"}, admin, approval).reason == "approval_token_replayed"),
    ]
    failed = [name for name, ok in assertions if not ok]
    for name, ok in assertions:
        console.print(f"{'[green]PASS[/green]' if ok else '[red]FAIL[/red]'} {name}")
    if failed:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
