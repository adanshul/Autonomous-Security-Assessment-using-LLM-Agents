"""Command-line entry point; offline operation is the default."""

from __future__ import annotations

import argparse
import json
import sys
from importlib.resources import files
from pathlib import Path

from . import __version__
from .benchmark import Run, benchmark
from .models import Assessment, Finding, Snapshot, digest
from .orchestrator import assess, verify_trace
from .planners import BedrockPlanner, ReferencePlanner, ReplayPlanner
from .reporting import write_bundle, write_json


def lab_path(name: str) -> Path:
    return Path(str(files("aegis_cloud").joinpath("labs", name)))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Aegis | Evidence-first AWS assessment research")
    root.add_argument("--version", action="version", version=__version__)
    subs = root.add_subparsers(dest="command", required=True)
    demo = subs.add_parser("demo", help="Run a synthetic lab without credentials or network")
    demo.add_argument("--out", type=Path, default=Path("runs/demo"))
    scan = subs.add_parser("assess", help="Assess a normalized snapshot")
    scan.add_argument("snapshot", type=Path)
    scan.add_argument("--engine", choices=["reference", "static", "bedrock"], default="reference")
    scan.add_argument("--out", type=Path, required=True)
    scan.add_argument("--max-steps", type=int, default=128)
    scan.add_argument("--model-id")
    scan.add_argument("--profile")
    scan.add_argument("--region", default="us-east-1")
    scan.add_argument("--max-model-tokens", type=int, default=100_000)
    scan.add_argument(
        "--allow-model-data-transfer",
        action="store_true",
        help="Allow this snapshot's resource/policy data to be sent to Bedrock",
    )
    gather = subs.add_parser("collect", help="Collect scoped AWS configuration with read-only APIs")
    gather.add_argument("--account-id", required=True)
    gather.add_argument("--region", action="append", required=True, dest="regions")
    gather.add_argument("--bucket", action="append", default=[], dest="buckets")
    gather.add_argument("--profile")
    gather.add_argument("--max-api-calls", type=int, default=500)
    gather.add_argument("--out", type=Path, required=True)
    bench = subs.add_parser(
        "benchmark", help="Score bundled labs and optionally import external runs"
    )
    bench.add_argument("--suite", type=Path, default=lab_path("labels.json"))
    bench.add_argument("--runs", type=Path, help="JSON array of adjudicated Run records")
    bench.add_argument("--seed", type=int, default=42)
    bench.add_argument("--baseline", default="static")
    bench.add_argument("--candidate", default="reference")
    bench.add_argument("--out", type=Path, default=Path("runs/benchmark"))
    diff = subs.add_parser("diff", help="Compare findings before and after a configuration change")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--out", type=Path, required=True)
    verify = subs.add_parser("verify", help="Verify a bundle's snapshot hash and event chain")
    verify.add_argument("bundle", type=Path)
    replay = subs.add_parser(
        "replay", help="Re-run recorded tool choices offline against their snapshot"
    )
    replay.add_argument("bundle", type=Path)
    replay.add_argument("--out", type=Path, required=True)
    export = subs.add_parser("export-run", help="Export an assessment for benchmark import")
    export.add_argument("report", type=Path)
    export.add_argument("--participant", required=True)
    export.add_argument("--method", help="Defaults to the assessment engine name")
    export.add_argument("--out", type=Path, required=True)
    return root


def load_report(path: Path) -> Assessment:
    return Assessment.model_validate_json(path.read_text(encoding="utf-8"))


def save_new(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command in ("assess", "demo"):
            demo = args.command == "demo"
            source = lab_path("exposed.json") if demo else args.snapshot
            snapshot = Snapshot.model_validate_json(source.read_text(encoding="utf-8"))
            if args.out.exists():
                raise ValueError("Output directory already exists; choose a new run directory")
            engine = "reference" if demo else args.engine
            if engine == "bedrock":
                if not args.allow_model_data_transfer:
                    raise ValueError(
                        "Bedrock requires --allow-model-data-transfer for snapshot data"
                    )
                if not args.model_id:
                    raise ValueError("Bedrock requires --model-id")
                from .aws import client_config, session

                client = session(args.profile, args.region).client(
                    "bedrock-runtime", config=client_config()
                )
                planner = BedrockPlanner(
                    client, args.model_id, max_total_tokens=args.max_model_tokens
                )
            else:
                planner = ReferencePlanner(snapshot, static=engine == "static")
            result = assess(snapshot, planner, max_steps=128 if demo else args.max_steps)
            write_bundle(result, snapshot, args.out)
            print(f"{result.status}: {len(result.findings)} findings | {args.out / 'report.html'}")
            return 0 if result.status == "completed" else 2
        if args.command == "collect":
            from .aws import ReadOnlyGateway, collect, session

            if args.out.exists():
                raise ValueError("Snapshot output already exists")
            gateway = ReadOnlyGateway(session(args.profile, args.regions[0]), args.max_api_calls)
            snapshot = collect(
                gateway, account_id=args.account_id, regions=args.regions, buckets=args.buckets
            )
            save_new(args.out, snapshot.model_dump())
            print(
                f"Collected {len(snapshot.catalog())} resources in {gateway.calls} calls. "
                f"{len(snapshot.collection_errors)} coverage errors. Saved {args.out}"
            )
            return 2 if snapshot.collection_errors else 0
        if args.command == "benchmark":
            if args.out.exists():
                raise ValueError("Output directory already exists")
            imported = json.loads(args.runs.read_text(encoding="utf-8")) if args.runs else []
            if not isinstance(imported, list):
                raise ValueError("Imported runs must be a JSON array")
            result = benchmark(
                args.suite,
                extra_runs=[Run.model_validate(r) for r in imported],
                seed=args.seed,
                baseline=args.baseline,
                candidate=args.candidate,
            )
            args.out.mkdir(parents=True, exist_ok=False)
            write_json(args.out / "benchmark.json", result)
            print(result["interpretation"])
            print(f"Scored {len(result['runs'])} runs | {args.out / 'benchmark.json'}")
            return 0
        if args.command == "diff":
            before, after = load_report(args.before), load_report(args.after)
            if before.status != "completed" or after.status != "completed":
                raise ValueError("Cannot compare incomplete assessments as remediation evidence")
            if (before.engine, before.model_id) != (after.engine, after.model_id):
                raise ValueError("Remediation comparisons require the same engine and model")
            left, right = {f.key for f in before.findings}, {f.key for f in after.findings}
            save_new(
                args.out,
                {
                    "no_longer_observed": sorted(left - right),
                    "introduced": sorted(right - left),
                    "persistent": sorted(left & right),
                    "before_sha256": before.snapshot_sha256,
                    "after_sha256": after.snapshot_sha256,
                    "note": "Absence of a finding is not proof of remediation; compare collection "
                    "coverage, evaluated actions, model limitations and functional behavior.",
                },
            )
            print(f"{len(left - right)} no longer observed; {len(right - left)} introduced")
            return 0
        if args.command in ("verify", "replay"):
            report = load_report(args.bundle / "report.json")
            snapshot = Snapshot.model_validate_json(
                (args.bundle / "snapshot.json").read_text(encoding="utf-8")
            )
            trace = [
                json.loads(line)
                for line in (args.bundle / "trace.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            valid = (
                digest(snapshot.model_dump()) == report.snapshot_sha256
                and trace == report.trace
                and verify_trace(trace, report.trace_sha256)
            )
            recorded = {}
            for event in trace:
                for raw in event.get("result", {}).get("accepted_findings", []):
                    finding = Finding.model_validate(raw)
                    recorded[finding.key] = finding
            valid = valid and sorted(recorded.values(), key=lambda f: f.key) == report.findings
            if args.command == "replay":
                if not valid or report.status != "completed":
                    raise ValueError("Replay requires an intact, completed evidence bundle")
                result = assess(snapshot, ReplayPlanner(trace), max_steps=len(trace) + 1)
                if result.findings != report.findings:
                    raise ValueError(
                        "Replayed findings differ; verifier code or evidence has changed"
                    )
                write_bundle(result, snapshot, args.out)
                print(
                    f"Replayed {len(result.findings)} findings offline | {args.out / 'report.html'}"
                )
                return 0
            print(
                "Evidence hashes verified (not a digital signature)"
                if valid
                else "Evidence mismatch"
            )
            return 0 if valid else 2
        if args.command == "export-run":
            report = load_report(args.report)
            run = Run(
                case_id=report.snapshot_id,
                participant=args.participant,
                method=args.method or report.engine,
                snapshot_sha256=report.snapshot_sha256,
                finding_keys=[f.key for f in report.findings],
                elapsed_seconds=report.elapsed_seconds,
                status=report.status,
            )
            save_new(args.out, [run.model_dump()])
            print(f"Saved benchmark run to {args.out}")
            return 0
    except (ValueError, OSError, KeyError) as exc:
        print(f"aegis: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            f"aegis: command failed ({type(exc).__name__}); check credentials and scope",
            file=sys.stderr,
        )
        return 2
    return 0
