"""Command line interface.

Commands:

    analyze   analyze a PCAP/PCAPNG file through the full chain
    capture   passive live capture on an interface
    inspect   show a packet or flow from a saved session
    report    regenerate reports from a saved session
    rules     list available detection rules
    doctor    check environment, libraries, privileges, and AI configuration
    version   print the version

Exit codes: 0 success, 1 runtime failure, 2 usage error, 3 environment problem.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from .config import AppConfig, load_config
from .logging_config import configure_logging, redact_text

TOOL_VERSION = "0.1.0"

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_USAGE_ERROR = 2
EXIT_ENVIRONMENT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scapy-ai",
        description=(
            "Evidence-based network packet analysis. Scapy extracts fields; an "
            "optional AI layer interprets them with traceable references."
        ),
        epilog=(
            "Examples:\n"
            "  scapy-ai analyze capture.pcap --output results/\n"
            "  scapy-ai analyze capture.pcap --no-ai --output results/\n"
            "  scapy-ai capture --interface eth0 --duration 60 --yes --output results/\n"
            "  scapy-ai rules list\n"
            "  scapy-ai doctor\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"scapy-ai {TOOL_VERSION}")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # analyze -----------------------------------------------------------------
    analyze = subparsers.add_parser("analyze", help="Analyze a PCAP/PCAPNG capture file.")
    analyze.add_argument("capture_file", help="Path to a .pcap or .pcapng file.")
    analyze.add_argument("--output", "-o", default=None, help="Directory for the session results.")
    analyze.add_argument("--config", "-c", default=None, help="Path to a YAML configuration file.")
    analyze.add_argument("--no-ai", action="store_true", help="Disable AI analysis.")
    analyze.add_argument("--provider", default=None, help="AI provider: mock or openai_compatible.")
    analyze.add_argument("--model", default=None, help="AI model name.")
    analyze.add_argument("--language", default=None, choices=["en", "ar"], help="AI output language.")
    analyze.add_argument("--max-packets", type=int, default=None, help="Stop after N packets.")
    analyze.add_argument("--batch-size", type=int, default=None, help="Packets per processing batch.")
    analyze.add_argument("--formats", default=None, help="Comma-separated report formats: json,html.")
    analyze.add_argument("--redact-ips", action="store_true", help="Mask private IP addresses.")
    analyze.add_argument("--redact-macs", action="store_true", help="Mask MAC address device parts.")
    analyze.add_argument("--log-level", default=None, help="DEBUG, INFO, WARNING, ERROR, CRITICAL.")
    analyze.add_argument("--log-format", default=None, choices=["text", "json"], help="Log format.")
    analyze.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output.")
    analyze.add_argument("--json-stdout", action="store_true", help="Print the report JSON to stdout.")

    # capture -----------------------------------------------------------------
    capture = subparsers.add_parser("capture", help="Passively capture live traffic.")
    capture.add_argument("--interface", "-i", default=None, help="Interface to capture on.")
    capture.add_argument("--duration", "-d", type=float, default=None, help="Capture seconds.")
    capture.add_argument("--max-packets", type=int, default=None, help="Stop after N packets.")
    capture.add_argument("--bpf", default=None, help="Optional BPF capture filter.")
    capture.add_argument("--output", "-o", default=None, help="Directory for the session results.")
    capture.add_argument("--config", "-c", default=None, help="Path to a YAML configuration file.")
    capture.add_argument("--no-ai", action="store_true", help="Disable AI analysis.")
    capture.add_argument("--provider", default=None, help="AI provider: mock or openai_compatible.")
    capture.add_argument("--model", default=None, help="AI model name.")
    capture.add_argument("--list-interfaces", action="store_true", help="List interfaces and exit.")
    capture.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Confirm that you are authorized to capture on this network.",
    )
    capture.add_argument("--formats", default=None, help="Comma-separated report formats: json,html.")
    capture.add_argument("--log-level", default=None, help="Log level.")
    capture.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output.")

    # inspect -----------------------------------------------------------------
    inspect = subparsers.add_parser("inspect", help="Inspect a packet or flow from a saved session.")
    inspect.add_argument("session_dir", help="Session directory or path to report.json.")
    group = inspect.add_mutually_exclusive_group(required=True)
    group.add_argument("--packet", type=int, default=None, help="Packet id to display.")
    group.add_argument("--flow", default=None, help="Flow id to display.")
    group.add_argument("--alert", default=None, help="Alert id to display.")
    group.add_argument("--summary", action="store_true", help="Show the session summary.")
    inspect.add_argument("--json", action="store_true", help="Emit JSON instead of text.")

    # report ------------------------------------------------------------------
    report = subparsers.add_parser("report", help="Regenerate reports from a saved session.")
    report.add_argument("session_dir", help="Session directory or path to report.json.")
    report.add_argument("--output", "-o", default=None, help="Output directory (defaults to the session).")
    report.add_argument("--formats", default="json,html", help="Comma-separated formats: json,html.")

    # rules -------------------------------------------------------------------
    rules = subparsers.add_parser("rules", help="Inspect the detection rule set.")
    rules_sub = rules.add_subparsers(dest="rules_command", metavar="SUBCOMMAND")
    rules_sub.add_parser("list", help="List all available rules.")

    # doctor ------------------------------------------------------------------
    doctor = subparsers.add_parser("doctor", help="Check environment and configuration.")
    doctor.add_argument("--config", "-c", default=None, help="Path to a YAML configuration file.")
    doctor.add_argument("--json", action="store_true", help="Emit JSON instead of text.")

    # version -----------------------------------------------------------------
    subparsers.add_parser("version", help="Print the tool version.")

    return parser


def _build_overrides(args: argparse.Namespace) -> dict[str, Any]:
    """Translate CLI flags into a config override mapping."""
    overrides: dict[str, Any] = {}

    capture_overrides: dict[str, Any] = {}
    if getattr(args, "max_packets", None) is not None:
        capture_overrides["max_packets"] = args.max_packets
    if getattr(args, "batch_size", None) is not None:
        capture_overrides["batch_size"] = args.batch_size
    if capture_overrides:
        overrides["capture"] = capture_overrides

    ai_overrides: dict[str, Any] = {}
    if getattr(args, "no_ai", False):
        ai_overrides["enabled"] = False
    if getattr(args, "provider", None):
        ai_overrides["provider"] = args.provider
    if getattr(args, "model", None):
        ai_overrides["model"] = args.model
    if getattr(args, "language", None):
        ai_overrides["language"] = args.language
    if ai_overrides:
        overrides["ai"] = ai_overrides

    privacy_overrides: dict[str, Any] = {}
    if getattr(args, "redact_ips", False):
        privacy_overrides["redact_private_ips"] = True
    if getattr(args, "redact_macs", False):
        privacy_overrides["redact_mac_addresses"] = True
    if privacy_overrides:
        overrides["privacy"] = privacy_overrides

    report_overrides: dict[str, Any] = {}
    if getattr(args, "output", None):
        report_overrides["output_dir"] = args.output
    formats = getattr(args, "formats", None)
    if formats:
        report_overrides["formats"] = [f.strip() for f in formats.split(",") if f.strip()]
    if report_overrides:
        overrides["report"] = report_overrides

    logging_overrides: dict[str, Any] = {}
    if getattr(args, "log_level", None):
        logging_overrides["level"] = args.log_level
    if getattr(args, "log_format", None):
        logging_overrides["format"] = args.log_format
    if logging_overrides:
        overrides["logging"] = logging_overrides

    return overrides


def _progress_printer(quiet: bool):
    """Build a progress callback that reports stage transitions and counts."""

    def printer(event: str, data: dict) -> None:
        if quiet:
            return
        if event == "progress":
            print(
                f"  read={data.get('packets_read', 0)} "
                f"parsed={data.get('packets_parsed', 0)} "
                f"failed={data.get('packets_failed', 0)}",
                file=sys.stderr,
            )
        elif event == "flows":
            print(f"  flows: {data.get('flow_count', 0)}", file=sys.stderr)
        elif event == "statistics":
            print(
                f"  packets: {data.get('total_packets', 0)} "
                f"bytes: {data.get('total_bytes', 0)}",
                file=sys.stderr,
            )
        elif event == "rules":
            print(f"  alerts: {data.get('alert_count', 0)}", file=sys.stderr)
        elif event == "ai_start":
            state = "enabled" if data.get("enabled") else "disabled"
            print(f"  ai: {state} (provider={data.get('provider')})", file=sys.stderr)
        elif event == "ai_done":
            status = "ok" if data.get("succeeded") else "no validated finding"
            print(f"  ai: {status} in {data.get('duration_seconds')}s", file=sys.stderr)

    return printer


def _write_reports(session, config: AppConfig) -> list[Path]:
    """Write the requested report formats and return the created paths."""
    from .reports.html_report import write_html_report
    from .reports.json_report import write_json_report

    output_dir = Path(config.report.output_dir) / session.session_id
    created: list[Path] = []
    if "json" in config.report.formats:
        created.append(write_json_report(session, output_dir))
    if "html" in config.report.formats:
        created.append(write_html_report(session, output_dir))
    return created


def _print_analysis_summary(session, created: list[Path]) -> None:
    stats = session.statistics or {}
    totals = stats.get("packet_totals", {})
    print("")
    print(f"Session:   {session.session_id}")
    print(f"Source:    {session.source}")
    print(f"Packets:   {session.packet_count} (failed to parse: {session.packets_failed})")
    print(f"Bytes:     {totals.get('bytes', 0)}")
    print(f"Flows:     {len(session.flows)}")
    print(f"Alerts:    {len(session.alerts)}")
    ai = session.ai_analysis
    if ai is None:
        print("AI:        not run")
    elif not ai.get("enabled"):
        print("AI:        disabled (--no-ai)")
    else:
        status = "validated" if ai.get("succeeded") else "not validated"
        print(f"AI:        {status} (provider={ai.get('provider')}, model={ai.get('model')})")
        if not ai.get("succeeded"):
            errors = ai.get("errors") or []
            if errors:
                print(f"           reason: {redact_text(str(errors[0]))[:160]}")
    if session.warnings:
        print(f"Warnings:  {len(session.warnings)}")
        for warning in session.warnings[:5]:
            print(f"           - {warning}")
    print("Reports:")
    for path in created:
        print(f"  {path}")
    print("")


# -- Command handlers --------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> int:
    from .capture.file_reader import CaptureFileError
    from .pipeline import Pipeline

    try:
        config = load_config(args.config, _build_overrides(args))
    except (ValueError, OSError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    configure_logging(config.logging.level, config.logging.format)

    pipeline = Pipeline(config, progress=_progress_printer(args.quiet))
    print(f"Analyzing {args.capture_file} ...", file=sys.stderr)
    try:
        result = pipeline.run_file(args.capture_file)
    except CaptureFileError as exc:
        print(f"Capture file error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR
    except Exception as exc:  # noqa: BLE001 - report the failure cleanly
        print(f"Analysis failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    created = _write_reports(result.session, config)
    if args.json_stdout:
        from .reports.json_report import render_json

        print(render_json(result.session))
    else:
        _print_analysis_summary(result.session, created)
    return EXIT_OK


def cmd_capture(args: argparse.Namespace) -> int:
    from .capture.live_capture import (
        CaptureRequest,
        LiveCapture,
        LiveCaptureError,
        list_interfaces,
    )
    from .capture.file_reader import ReadStats
    from .pipeline import Pipeline

    if args.list_interfaces:
        interfaces, reason = list_interfaces()
        if reason:
            print(reason, file=sys.stderr)
        for info in interfaces:
            loopback = " (loopback)" if info.is_loopback else ""
            addresses = ", ".join(info.addresses) if info.addresses else "no address reported"
            print(f"{info.name}{loopback}  {addresses}")
        return EXIT_OK if interfaces else EXIT_ENVIRONMENT_ERROR

    try:
        config = load_config(args.config, _build_overrides(args))
    except (ValueError, OSError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    configure_logging(config.logging.level, config.logging.format)

    interface = args.interface or config.capture.interface
    duration = args.duration if args.duration is not None else config.capture.duration
    max_packets = args.max_packets if args.max_packets is not None else config.capture.max_packets

    if not interface:
        print(
            "An interface is required. Use --interface or run 'scapy-ai capture "
            "--list-interfaces'.",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    request = CaptureRequest(
        interface=interface,
        duration=duration,
        max_packets=max_packets,
        bpf_filter=args.bpf,
        snaplen=config.capture.snaplen,
        promisc=config.capture.promisc,
        confirmed=args.yes,
    )

    if not args.yes:
        print(
            "Live capture is passive but still observes real traffic. Confirm that you "
            "are authorized to monitor this network, then re-run with --yes.",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    try:
        request.validate()
    except LiveCaptureError as exc:
        print(f"Invalid capture request: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    if not args.quiet:
        print(
            f"Capturing on {interface} "
            f"(duration={duration}, max_packets={max_packets}). Press Ctrl+C to stop.",
            file=sys.stderr,
        )

    capture = LiveCapture(request)
    try:
        outcome = capture.run()
    except LiveCaptureError as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        return EXIT_ENVIRONMENT_ERROR

    if not args.quiet:
        print(
            f"Capture finished: {outcome.packets_seen} packets "
            f"({outcome.stop_reason}) in {outcome.duration:.2f}s",
            file=sys.stderr,
        )

    if outcome.stop_reason == "capture_error":
        for error in outcome.errors:
            print(f"Capture error: {error}", file=sys.stderr)
        return EXIT_ENVIRONMENT_ERROR

    if outcome.packets_seen == 0:
        for warning in outcome.errors:
            print(f"Capture warning: {warning}", file=sys.stderr)

    read_stats = ReadStats(
        packets_read=outcome.packets_seen,
        packets_parsed=outcome.packets_seen - outcome.packets_failed,
        packets_failed=outcome.packets_failed,
        capture_format="live",
        read_errors=list(outcome.errors),
    )

    pipeline = Pipeline(config, progress=_progress_printer(args.quiet))
    result = pipeline.run_records(
        outcome.records,
        source=f"live:{interface}",
        source_type="live",
        read_stats=read_stats,
    )

    created = _write_reports(result.session, config)
    _print_analysis_summary(result.session, created)
    return EXIT_OK


def _resolve_session_path(session_dir: str) -> Path:
    path = Path(session_dir)
    if path.is_dir():
        return path / "report.json"
    return path


def cmd_inspect(args: argparse.Namespace) -> int:
    from .reports.json_report import read_json_report

    path = _resolve_session_path(args.session_dir)
    if not path.exists():
        print(f"Session report not found: {path}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    try:
        session = read_json_report(path)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Could not read session: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    payload: Optional[dict] = None

    if args.packet is not None:
        payload = next(
            (p for p in session.packets if p.get("packet_id") == args.packet), None
        )
        if payload is None:
            print(
                f"Packet {args.packet} is not present in the stored session detail. "
                "It may have been beyond the report packet limit.",
                file=sys.stderr,
            )
            return EXIT_RUNTIME_ERROR
    elif args.flow:
        payload = next((f for f in session.flows if f.get("flow_id") == args.flow), None)
        if payload is None:
            print(f"Flow {args.flow} not found in this session.", file=sys.stderr)
            return EXIT_RUNTIME_ERROR
    elif args.alert:
        payload = next((a for a in session.alerts if a.get("alert_id") == args.alert), None)
        if payload is None:
            print(f"Alert {args.alert} not found in this session.", file=sys.stderr)
            return EXIT_RUNTIME_ERROR
    else:
        payload = {
            "session_id": session.session_id,
            "source": session.source,
            "source_type": session.source_type,
            "packet_count": session.packet_count,
            "packets_failed": session.packets_failed,
            "flow_count": len(session.flows),
            "alert_count": len(session.alerts),
            "statistics": session.statistics.get("packet_totals", {}),
            "ai": {
                "enabled": (session.ai_analysis or {}).get("enabled"),
                "succeeded": (session.ai_analysis or {}).get("succeeded"),
                "provider": (session.ai_analysis or {}).get("provider"),
                "finding_type": ((session.ai_analysis or {}).get("finding") or {}).get(
                    "finding_type"
                ),
            },
            "warnings": session.warnings,
            "limitations": session.limitations,
        }

    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    else:
        _print_inspect_text(payload, args)
    return EXIT_OK


def _print_inspect_text(payload: dict, args: argparse.Namespace) -> None:
    if args.packet is not None:
        print(f"Packet {payload.get('packet_id')}")
        print(f"  timestamp:   {payload.get('timestamp')}")
        print(f"  length:      {payload.get('captured_length')}")
        print(f"  protocols:   {', '.join(payload.get('protocols') or []) or 'none identified'}")
        print(f"  source:      {payload.get('src_ip')}:{payload.get('src_port')}")
        print(f"  destination: {payload.get('dst_ip')}:{payload.get('dst_port')}")
        print(f"  transport:   {payload.get('transport_protocol')}")
        if payload.get("tcp_flags"):
            print(f"  tcp flags:   {payload.get('tcp_flags')}")
        if payload.get("dns_query"):
            print(f"  dns query:   {payload.get('dns_query')} ({payload.get('dns_query_type')})")
        if payload.get("http_host"):
            print(f"  http host:   {payload.get('http_host')}")
        if payload.get("tls_sni"):
            print(f"  tls sni:     {payload.get('tls_sni')}")
        print(f"  parse:       {payload.get('parse_status')}")
        if payload.get("parse_warnings"):
            print(f"  warnings:    {', '.join(payload['parse_warnings'])}")
        return

    if args.flow:
        print(f"Flow {payload.get('flow_id')}")
        print(f"  endpoints:   {payload.get('src_ip')}:{payload.get('src_port')} <-> "
              f"{payload.get('dst_ip')}:{payload.get('dst_port')}")
        print(f"  protocol:    {payload.get('transport_protocol')}")
        print(f"  packets:     {payload.get('total_packets')} "
              f"(forward {payload.get('packets_forward')}, reverse {payload.get('packets_reverse')})")
        print(f"  bytes:       {payload.get('total_bytes')} "
              f"(forward {payload.get('bytes_forward')}, reverse {payload.get('bytes_reverse')})")
        print(f"  duration:    {payload.get('duration')}s")
        print(f"  tcp flags:   {payload.get('tcp_flag_counts')}")
        print(f"  syn only:    {payload.get('is_syn_only')}")
        print(f"  packets:     {payload.get('packet_ids')}")
        return

    if args.alert:
        print(f"Alert {payload.get('alert_id')} ({payload.get('rule_id')})")
        print(f"  rule:        {payload.get('rule_name')}")
        print(f"  severity:    {payload.get('severity')}")
        print(f"  description: {payload.get('description')}")
        print(f"  reason:      {payload.get('reason')}")
        print(f"  metrics:     {json.dumps(payload.get('metrics', {}), ensure_ascii=False)}")
        print(f"  evidence:    {', '.join(payload.get('evidence_refs') or [])}")
        print("  limitations:")
        for item in payload.get("limitations") or []:
            print(f"    - {item}")
        return

    print("Session summary")
    for key, value in payload.items():
        if isinstance(value, (dict, list)):
            print(f"  {key}: {json.dumps(value, ensure_ascii=False, default=str)}")
        else:
            print(f"  {key}: {value}")


def cmd_report(args: argparse.Namespace) -> int:
    from .reports.html_report import write_html_report
    from .reports.json_report import read_json_report, write_json_report

    path = _resolve_session_path(args.session_dir)
    if not path.exists():
        print(f"Session report not found: {path}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    try:
        session = read_json_report(path)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Could not read session: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    output_dir = Path(args.output) if args.output else path.parent
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    created: list[Path] = []
    for fmt in formats:
        if fmt == "json":
            created.append(write_json_report(session, output_dir))
        elif fmt == "html":
            created.append(write_html_report(session, output_dir))
        else:
            print(f"Unsupported report format: {fmt}", file=sys.stderr)
            return EXIT_USAGE_ERROR

    print(f"Reports written for session {session.session_id}:")
    for item in created:
        print(f"  {item}")
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    from .analysis.rule_engine import RuleEngine

    if args.rules_command != "list":
        print("Usage: scapy-ai rules list", file=sys.stderr)
        return EXIT_USAGE_ERROR

    engine = RuleEngine()
    print(f"{len(engine.list_rules())} detection rules:\n")
    for definition in engine.list_rules():
        print(f"{definition.rule_id}  {definition.name}  [{definition.severity}]")
        print(f"    {definition.description}")
        print("    Limitations:")
        for item in definition.limitations:
            print(f"      - {item}")
        print("")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    from .capture.live_capture import check_capture_privileges, list_interfaces

    checks: list[dict[str, Any]] = []
    problems = 0

    checks.append(
        {
            "check": "python",
            "status": "ok",
            "detail": f"{sys.version.split()[0]}",
        }
    )

    try:
        import scapy

        checks.append(
            {"check": "scapy", "status": "ok", "detail": getattr(scapy, "__version__", "unknown")}
        )
    except Exception as exc:  # noqa: BLE001
        problems += 1
        checks.append({"check": "scapy", "status": "error", "detail": str(exc)})

    try:
        import yaml  # noqa: F401

        checks.append({"check": "pyyaml", "status": "ok", "detail": "available"})
    except Exception as exc:  # noqa: BLE001
        problems += 1
        checks.append({"check": "pyyaml", "status": "error", "detail": str(exc)})

    try:
        config = load_config(args.config)
        checks.append(
            {
                "check": "config",
                "status": "ok",
                "detail": f"provider={config.ai.provider} ai_enabled={config.ai.enabled} "
                f"output_dir={config.report.output_dir}",
            }
        )
    except (ValueError, OSError) as exc:
        problems += 1
        config = None
        checks.append({"check": "config", "status": "error", "detail": str(exc)})

    if config is not None:
        from .ai.service import build_provider

        try:
            provider = build_provider(config.ai)
            available = provider.is_available()
            description = provider.describe()
            # describe() includes a boolean key-presence flag, never the key itself.
            if available:
                status, detail = "ok", json.dumps(description, ensure_ascii=False)
            else:
                status = "warn"
                detail = (
                    "Provider is not fully configured; analysis will continue without AI. "
                    + json.dumps(description, ensure_ascii=False)
                )
            checks.append({"check": "ai_provider", "status": status, "detail": detail})
        except ValueError as exc:
            problems += 1
            checks.append({"check": "ai_provider", "status": "error", "detail": str(exc)})

    privileged, privilege_detail = check_capture_privileges()
    checks.append(
        {
            "check": "capture_privileges",
            "status": "ok" if privileged else "warn",
            "detail": privilege_detail,
        }
    )

    interfaces, reason = list_interfaces()
    if interfaces:
        checks.append(
            {
                "check": "interfaces",
                "status": "ok",
                "detail": ", ".join(info.name for info in interfaces),
            }
        )
    else:
        checks.append(
            {
                "check": "interfaces",
                "status": "warn",
                "detail": reason or "No interfaces detected.",
            }
        )

    output_dir = config.report.output_dir if config else "results"
    try:
        target = Path(output_dir)
        target.mkdir(parents=True, exist_ok=True)
        probe = target / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        checks.append({"check": "output_writable", "status": "ok", "detail": str(target.resolve())})
    except OSError as exc:
        problems += 1
        checks.append({"check": "output_writable", "status": "error", "detail": str(exc)})

    if args.json:
        print(json.dumps({"checks": checks, "problems": problems}, indent=2, ensure_ascii=False))
    else:
        print("Environment check\n")
        for check in checks:
            marker = {"ok": "OK  ", "warn": "WARN", "error": "FAIL"}.get(check["status"], "?   ")
            print(f"[{marker}] {check['check']}: {check['detail']}")
        print("")
        if problems:
            print(f"{problems} problem(s) found that must be resolved before a full run.")
        else:
            print("No blocking problems found.")

    return EXIT_ENVIRONMENT_ERROR if problems else EXIT_OK


def cmd_version(args: argparse.Namespace) -> int:  # noqa: ARG001
    print(f"scapy-ai {TOOL_VERSION}")
    return EXIT_OK


HANDLERS = {
    "analyze": cmd_analyze,
    "capture": cmd_capture,
    "inspect": cmd_inspect,
    "report": cmd_report,
    "rules": cmd_rules,
    "doctor": cmd_doctor,
    "version": cmd_version,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_USAGE_ERROR

    handler = HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return EXIT_USAGE_ERROR

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":
    sys.exit(main())
