"""``tobira`` command line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import __version__

# ------------------------------------------------------------------- demo


async def _demo(workdir: Path | None, quiet: bool) -> int:
    from .client import AccessDenied
    from .lab import DEFAULT_CONFIG_DIR, temporary_lab

    ctx = (
        temporary_lab(echo_audit=not quiet)
        if workdir is None
        else _persistent(workdir, echo_audit=not quiet)
    )
    async with ctx as lab:  # type: ignore[attr-defined]
        print("\n== Tobira lab ==")
        print(f"broker        : {lab.host}:{lab.broker.client_port} (clients), "
              f"{lab.broker.connector_port} (connectors)")
        print(f"connectors    : {', '.join(sorted(lab.connectors))}")
        print(f"private apps  : {', '.join(sorted(lab.apps))}")
        print(f"audit log     : {lab.emitter.path}")
        print(f"config        : {DEFAULT_CONFIG_DIR}")

        print("\n== Aiko (finance, MFA, hardened laptop) ==")
        aiko = await lab.client_for("aiko")
        print(f"  broker says she may reach: {aiko.apps}")
        body = await aiko.request(
            "payroll", b"GET /payslip HTTP/1.1\r\nHost: payroll\r\n\r\n"
        )
        payload = body.split(b"\r\n\r\n")[-1].decode().strip().replace("\n", " | ")
        print("  payroll replied:", payload)

        port = await aiko.listen("wiki")
        print(f"  wiki is now on 127.0.0.1:{port} for ordinary tools (curl, browser)")

        print("\n== Ben (employee, no MFA, 21-day-old patches) ==")
        ben = await lab.client_for("ben")
        print(f"  broker says he may reach: {ben.apps}")
        for app in ("payroll", "factory-hmi"):
            try:
                await ben.open(app)
                print(f"  {app}: ALLOWED (unexpected)")
            except AccessDenied as exc:
                print(f"  {app}: denied ({exc.reason})")

        print("\n== Chen (OT engineer) turns off EDR mid-session ==")
        chen = await lab.client_for("chen")
        stream = await chen.open("factory-hmi")
        await stream.send(b"GET /status HTTP/1.1\r\n\r\n")
        await stream.read_all(timeout=2.0)
        print("  HMI session established")
        from .posture import DeviceState

        reply = await chen.refresh_posture(
            DeviceState("workstation-chen", os_patch_age_days=1, edr_running=False)
        )
        print(f"  after re-attestation: score {reply.get('score')}, "
              f"revoked {reply.get('revoked')}")

        print(f"\n{len(lab.emitter.events)} audit events written.\n")
    return 0


def _persistent(workdir: Path, *, echo_audit: bool):
    from contextlib import asynccontextmanager

    from .lab import Lab

    @asynccontextmanager
    async def runner():
        lab = Lab(workdir=workdir, echo_audit=echo_audit)
        await lab.start()
        try:
            yield lab
        finally:
            await lab.stop()

    return runner()


# ----------------------------------------------------------------- attack


async def _attack(out: Path | None, quiet: bool) -> int:
    from .attacks import run_all
    from .lab import temporary_lab
    from .report import build_report, console_summary
    from .siem import DetectionEngine

    async with temporary_lab(echo_audit=False) as lab:
        engine = DetectionEngine()
        lab.emitter.subscribe(engine.consume)

        if not quiet:
            print("\nRunning adversary scenarios against the live broker:\n")
        results = await run_all(lab, verbose=not quiet)

        print()
        print(console_summary(results, engine.alerts))

        report = build_report(results, engine.alerts, lab.emitter.events)
        target = out or Path("reports/control-verification.md")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(report)
        print(f"\nReport written to {target}")

        log_copy = target.parent / "audit-sample.ecs.json"
        log_copy.write_text(
            "\n".join(json.dumps(doc, separators=(",", ":")) for doc in lab.emitter.events)
            + "\n"
        )
        print(f"Audit stream written to {log_copy}")

        return 0 if all(r.blocked for r in results) else 1


# ----------------------------------------------------------------- detect


def _detect(path: Path) -> int:
    from .siem import DetectionEngine

    engine = DetectionEngine()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                engine.consume(json.loads(line))
    print(engine.report())
    return 0


# -------------------------------------------------------------------- pki


def _pki(directory: Path) -> int:
    from .pki import CertificateAuthority

    ca = CertificateAuthority(directory)
    ca.ensure()
    print(f"CA ready at {ca.cert_path}")
    return 0


# ------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tobira",
        description="Tobira - a zero trust private access lab "
        "(broker/connector model, device posture, SIEM logging)",
    )
    parser.add_argument("--version", action="version", version=f"tobira {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="bring the lab up and walk through it")
    demo.add_argument("--workdir", type=Path, default=None, help="keep PKI and logs here")
    demo.add_argument("--quiet", action="store_true", help="hide the live audit stream")

    attack = sub.add_parser("attack", help="run the adversary scenarios and write a report")
    attack.add_argument("--out", type=Path, default=None, help="report path")
    attack.add_argument("--quiet", action="store_true")

    detect = sub.add_parser("detect", help="run detection rules over an ECS log file")
    detect.add_argument("logfile", type=Path)

    pki = sub.add_parser("pki", help="create a lab certificate authority")
    pki.add_argument("--dir", type=Path, default=Path("pki"))

    args = parser.parse_args(argv)

    if args.command == "demo":
        return asyncio.run(_demo(args.workdir, args.quiet))
    if args.command == "attack":
        return asyncio.run(_attack(args.out, args.quiet))
    if args.command == "detect":
        return _detect(args.logfile)
    if args.command == "pki":
        return _pki(args.dir)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
