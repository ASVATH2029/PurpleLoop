#!/usr/bin/env python3
"""
nuclei_runner.py — PurpleLoop Nuclei Template Simulation Runner

Loads Nuclei-format YAML attack templates, executes them in dry-run
(synthetic CloudTrail log generation) or live mode (actual AWS API calls),
and outputs structured CloudTrail-compatible JSON logs for the detection
and evaluation pipeline.

Usage:
    python simulation/nuclei_runner.py --templates nuclei_templates/ --dry-run --output logs/
    python simulation/nuclei_runner.py --templates nuclei_templates/aws-iam-privesc/ --output logs/
    python simulation/nuclei_runner.py --templates nuclei_templates/ --mutate --rounds 5 --output logs/
"""

import argparse
import copy
import hashlib
import json
import os
import random
import re
import string
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


# ── Constants ────────────────────────────────────────────────────────────

CLOUDTRAIL_SCHEMA_VERSION = "1.08"
DEFAULT_REGION = "us-east-1"
LOG_FILENAME_TEMPLATE = "nuclei_sim_{timestamp}_{template_id}.json"


# ── Template Loader ─────────────────────────────────────────────────────

def discover_templates(template_path: str) -> list[Path]:
    """Recursively discover all .yaml Nuclei templates under a path."""
    root = Path(template_path)
    if root.is_file() and root.suffix in (".yaml", ".yml"):
        return [root]
    if root.is_dir():
        templates = sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml"))
        # Exclude README and non-template files
        return [t for t in templates if t.name != "README.md"]
    return []


def load_template(path: Path) -> dict:
    """Load and parse a single Nuclei template YAML file."""
    with open(path, "r") as f:
        content = f.read()
    template = yaml.safe_load(content)
    if not template or "id" not in template:
        raise ValueError(f"Invalid template (missing 'id'): {path}")
    return template


# ── Variable Resolution ─────────────────────────────────────────────────

def resolve_variables(template: dict, overrides: dict | None = None) -> dict:
    """
    Resolve {{variable}} placeholders in the template using the template's
    own 'variables' block and any external overrides (e.g., from the mutation
    engine).
    """
    variables = template.get("variables", {})
    if overrides:
        variables.update(overrides)

    # Add dynamic variables
    variables.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    variables.setdefault("uuid", str(uuid.uuid4()))
    variables.setdefault("random_hex_16", "".join(
        random.choices(string.hexdigits[:16].upper(), k=16)
    ))

    def _substitute(obj: Any) -> Any:
        if isinstance(obj, str):
            # Replace {{var}} patterns
            def replacer(match):
                var_name = match.group(1).strip()
                return str(variables.get(var_name, match.group(0)))
            return re.sub(r"\{\{(\w+)\}\}", replacer, obj)
        elif isinstance(obj, dict):
            return {k: _substitute(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_substitute(item) for item in obj]
        return obj

    return _substitute(template)


# ── CloudTrail Event Generator ──────────────────────────────────────────

def generate_cloudtrail_event(
    step: dict,
    template_info: dict,
    iteration: int = 0,
    region: str = DEFAULT_REGION,
) -> dict:
    """
    Generate a single CloudTrail-compatible JSON event from a template step.
    """
    ct_event = step.get("cloudtrail_event", {})
    event_time = datetime.now(timezone.utc)

    # Build the full CloudTrail event envelope
    event = {
        "eventVersion": CLOUDTRAIL_SCHEMA_VERSION,
        "eventTime": event_time.isoformat(),
        "eventSource": ct_event.get("eventSource", "unknown.amazonaws.com"),
        "eventName": ct_event.get("eventName", step.get("action", "Unknown")),
        "awsRegion": region,
        "sourceIPAddress": ct_event.get("sourceIPAddress", "198.51.100.42"),
        "userAgent": ct_event.get("userAgent", "aws-cli/2.15.0"),
        "requestParameters": ct_event.get("requestParameters", step.get("parameters", {})),
        "responseElements": ct_event.get("responseElements", None),
        "readOnly": ct_event.get("readOnly", False),
        "eventType": "AwsApiCall",
        "recipientAccountId": ct_event.get(
            "recipientAccountId",
            template_info.get("variables", {}).get("target_account", "123456789012"),
        ),
        "eventID": str(uuid.uuid4()),
        "userIdentity": ct_event.get("userIdentity", {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "arn": f"arn:aws:iam::123456789012:user/red-team-sim",
            "accountId": "123456789012",
            "userName": "red-team-sim",
        }),
        # PurpleLoop-specific metadata
        "_purpleloop": {
            "template_id": template_info.get("id", "unknown"),
            "template_name": template_info.get("info", {}).get("name", "Unknown"),
            "step_action": step.get("action", "unknown"),
            "step_description": step.get("description", ""),
            "iteration": iteration,
            "severity": template_info.get("info", {}).get("severity", "unknown"),
            "mitre_attack": template_info.get("info", {}).get("metadata", {}).get(
                "mitre_attack", {}
            ),
            "simulated": True,
            "generated_at": event_time.isoformat(),
        },
    }

    return event


def expand_repeating_steps(steps: list[dict]) -> list[dict]:
    """Expand steps with 'repeat' into individual step instances."""
    expanded = []
    for step in steps:
        repeat_count = int(step.get("repeat", 1))
        for i in range(repeat_count):
            step_copy = copy.deepcopy(step)
            # Replace {{iteration}} in the step
            step_copy = json.loads(
                json.dumps(step_copy).replace("{{iteration}}", str(i))
            )
            expanded.append((step_copy, i))
    return expanded


# ── Matcher Evaluation ──────────────────────────────────────────────────

def evaluate_matchers(events: list[dict], matchers: list[dict]) -> list[dict]:
    """
    Evaluate template matchers against generated events to determine
    if the simulated attack would be detectable.
    """
    results = []
    for matcher in matchers:
        match_type = matcher.get("type", "cloudtrail")
        match_name = matcher.get("name", "unnamed")

        if match_type == "cloudtrail":
            fields = matcher.get("fields", [])
            condition = matcher.get("condition", "and")
            threshold = matcher.get("threshold", {})

            matched_events = []
            for event in events:
                field_matches = []
                for field_expr in fields:
                    field_matches.append(_eval_field(event, field_expr))

                if condition == "and" and all(field_matches):
                    matched_events.append(event)
                elif condition == "or" and any(field_matches):
                    matched_events.append(event)

            # Check threshold
            if threshold:
                count = threshold.get("count", 1)
                triggered = len(matched_events) >= count
            else:
                triggered = len(matched_events) > 0

            results.append({
                "matcher": match_name,
                "type": match_type,
                "triggered": triggered,
                "matched_count": len(matched_events),
                "threshold": threshold,
            })

        elif match_type == "sequence":
            seq_events = matcher.get("events", [])
            within = matcher.get("within", 300)
            triggered = _check_sequence(events, seq_events, within)
            results.append({
                "matcher": match_name,
                "type": match_type,
                "triggered": triggered,
                "sequence_length": len(seq_events),
                "within_seconds": within,
            })

    return results


def _eval_field(event: dict, expr: str) -> bool:
    """Evaluate a simple field expression against a CloudTrail event."""
    # Support expressions like: eventName == "StopLogging"
    if "==" in expr:
        field, value = expr.split("==", 1)
        field = field.strip()
        value = value.strip().strip('"').strip("'")
        actual = _get_nested(event, field)
        return str(actual) == value
    elif "contains" in expr:
        field, value = expr.split("contains", 1)
        field = field.strip()
        value = value.strip().strip('"').strip("'")
        actual = _get_nested(event, field)
        return value in str(actual) if actual else False
    elif "!=" in expr:
        field, value = expr.split("!=", 1)
        field = field.strip()
        value = value.strip().strip('"').strip("'")
        actual = _get_nested(event, field)
        return str(actual) != value
    return False


def _get_nested(data: dict, path: str) -> Any:
    """Get a nested value from a dict using dot notation."""
    keys = path.split(".")
    current = data
    for key in keys:
        key = key.strip()
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
        if current is None:
            return None
    return current


def _check_sequence(events: list[dict], seq_exprs: list[str], within: int) -> bool:
    """Check if a sequence of events occurs within a time window."""
    # Simplified: check that events matching each expression appear in order
    seq_idx = 0
    for event in events:
        if seq_idx < len(seq_exprs):
            parts = seq_exprs[seq_idx].split("&&")
            all_match = all(_eval_field(event, p.strip()) for p in parts)
            if all_match:
                seq_idx += 1
    return seq_idx == len(seq_exprs)


# ── Mutation Engine Integration ─────────────────────────────────────────

MUTATION_PARAMETERS = {
    "delay_seconds": [0, 1, 2, 5, 10, 30, 60, 120],
    "batch_size": [1, 5, 10, 25, 50, 100, 500],
    "user_agent": [
        "aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0",
        "Boto3/1.28.0 Python/3.11.6",
        "Mozilla/5.0 (compatible; aws-sdk-go/1.44.0)",
        "aws-sdk-java/2.20.0 Linux/5.15.0",
        "terraform/1.5.0",
        "CloudFormation/2.0",
        "console.amazonaws.com",
    ],
    "source_ip": [
        "198.51.100.42",
        "203.0.113.10",
        "10.0.0.50",
        "172.16.0.100",
        "192.168.1.1",
    ],
    "session_name": [
        "red-team-sim",
        "deploy-pipeline",
        "monitoring-svc",
        "backup-job",
        "ci-cd-runner",
        "cloudformation-exec",
    ],
}


def generate_mutation(template: dict, round_num: int) -> dict:
    """
    Generate a mutated variant of a template by randomly varying
    attack parameters.  This simulates the RL-based evasion search.
    """
    mutated = copy.deepcopy(template)
    overrides = {}

    # Randomly mutate 2-4 parameters
    params_to_mutate = random.sample(
        list(MUTATION_PARAMETERS.keys()),
        k=min(random.randint(2, 4), len(MUTATION_PARAMETERS)),
    )

    for param in params_to_mutate:
        overrides[param] = random.choice(MUTATION_PARAMETERS[param])

    # Update template variables
    if "variables" not in mutated:
        mutated["variables"] = {}
    mutated["variables"].update(overrides)

    # Tag the mutation
    if "info" not in mutated:
        mutated["info"] = {}
    if "metadata" not in mutated["info"]:
        mutated["info"]["metadata"] = {}
    mutated["info"]["metadata"]["mutation"] = {
        "round": round_num,
        "mutated_params": overrides,
        "mutation_id": hashlib.md5(
            json.dumps(overrides, sort_keys=True).encode()
        ).hexdigest()[:8],
    }

    return mutated


# ── Simulation Execution ────────────────────────────────────────────────

def run_template(
    template: dict,
    dry_run: bool = True,
    verbose: bool = False,
) -> dict:
    """
    Execute a single Nuclei template, generating CloudTrail events
    for each attack step.

    Returns a simulation result dict with events, matchers, and metadata.
    """
    template_id = template.get("id", "unknown")
    info = template.get("info", {})
    attack = template.get("attack", {})
    matchers = template.get("matchers", [])
    extractors = template.get("extractors", [])

    if verbose:
        print(f"\n{'='*70}")
        print(f"  Template: {template_id}")
        print(f"  Name:     {info.get('name', 'Unknown')}")
        print(f"  Severity: {info.get('severity', 'unknown')}")
        print(f"  Mode:     {'DRY-RUN (synthetic)' if dry_run else 'LIVE (AWS API)'}")
        print(f"{'='*70}")

    # Resolve all variables
    resolved = resolve_variables(template)
    attack = resolved.get("attack", {})
    steps = attack.get("steps", [])

    # Expand repeated steps
    expanded_steps = expand_repeating_steps(steps)

    # Generate CloudTrail events for each step
    events = []
    for step, iteration in expanded_steps:
        delay = float(step.get("delay", 0))

        if dry_run:
            # Synthetic mode: generate event without making real API calls
            event = generate_cloudtrail_event(step, resolved, iteration)
            events.append(event)

            if verbose:
                action = step.get("action", "unknown")
                desc = step.get("description", "")
                print(f"  [SIM] {action}: {desc}")

            if delay > 0 and not dry_run:
                time.sleep(delay)
        else:
            # Live mode would execute actual AWS API calls here
            # (requires boto3 and valid credentials)
            print(f"  [LIVE] Would execute: {step.get('action', 'unknown')}")
            event = generate_cloudtrail_event(step, resolved, iteration)
            events.append(event)

    # Evaluate matchers
    matcher_results = evaluate_matchers(events, matchers)

    # Extract values
    extracted = {}
    for extractor in extractors:
        ext_name = extractor.get("name", "unnamed")
        json_paths = extractor.get("json", [])
        for event in events:
            for jp in json_paths:
                # Simple JSONPath-like extraction
                path = jp.lstrip(".")
                value = _get_nested(event, path)
                if value:
                    extracted[ext_name] = value

    result = {
        "template_id": template_id,
        "template_name": info.get("name", "Unknown"),
        "severity": info.get("severity", "unknown"),
        "mitre_attack": info.get("metadata", {}).get("mitre_attack", {}),
        "tags": info.get("tags", "").split(",") if isinstance(info.get("tags"), str) else info.get("tags", []),
        "execution_mode": "dry-run" if dry_run else "live",
        "events_generated": len(events),
        "events": events,
        "matcher_results": matcher_results,
        "extracted_values": extracted,
        "mutation_info": info.get("metadata", {}).get("mutation", None),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if verbose:
        print(f"\n  Results:")
        print(f"    Events generated: {len(events)}")
        for mr in matcher_results:
            status = "✅ TRIGGERED" if mr["triggered"] else "❌ NOT TRIGGERED"
            print(f"    Matcher '{mr['matcher']}': {status}")
        if extracted:
            print(f"    Extracted: {json.dumps(extracted, indent=2)}")

    return result


# ── Output ──────────────────────────────────────────────────────────────

def write_results(
    results: list[dict],
    output_dir: str,
    verbose: bool = False,
) -> list[str]:
    """Write simulation results as CloudTrail-compatible JSON log files."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    written_files = []

    # Aggregate all events into a single CloudTrail log file
    all_events = []
    for result in results:
        all_events.extend(result["events"])

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_file = output_path / f"nuclei_sim_{timestamp}.json"

    cloudtrail_log = {
        "Records": all_events,
        "_metadata": {
            "generator": "purpleloop-nuclei-runner",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(all_events),
            "templates_executed": len(results),
            "template_ids": [r["template_id"] for r in results],
        },
    }

    with open(log_file, "w") as f:
        json.dump(cloudtrail_log, f, indent=2, default=str)
    written_files.append(str(log_file))

    if verbose:
        print(f"\n  📝 Wrote {len(all_events)} events to {log_file}")

    # Write a summary report
    summary_file = output_path / f"nuclei_sim_{timestamp}_summary.json"
    summary = {
        "execution_summary": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_templates": len(results),
            "total_events": len(all_events),
            "templates": [],
        }
    }

    for result in results:
        template_summary = {
            "template_id": result["template_id"],
            "template_name": result["template_name"],
            "severity": result["severity"],
            "mitre_attack": result["mitre_attack"],
            "events_generated": result["events_generated"],
            "matcher_results": result["matcher_results"],
            "extracted_values": result["extracted_values"],
            "mutation_info": result["mutation_info"],
        }
        summary["execution_summary"]["templates"].append(template_summary)

    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    written_files.append(str(summary_file))

    if verbose:
        print(f"  📊 Wrote summary to {summary_file}")

    return written_files


# ── CLI ─────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PurpleLoop Nuclei Template Simulation Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry-run all templates (generate synthetic logs)
  python simulation/nuclei_runner.py --templates nuclei_templates/ --dry-run --output logs/

  # Run specific attack category
  python simulation/nuclei_runner.py --templates nuclei_templates/aws-iam-privesc/ --output logs/

  # Run with mutation engine (evasion search)
  python simulation/nuclei_runner.py --templates nuclei_templates/ --mutate --rounds 5 --output logs/

  # Verbose output with variable overrides
  python simulation/nuclei_runner.py --templates nuclei_templates/ --dry-run -v \\
      --var delay_seconds=10 --var user_agent="custom-agent/1.0"
        """,
    )

    parser.add_argument(
        "--templates", "-t",
        required=True,
        help="Path to templates directory or a single template YAML file",
    )
    parser.add_argument(
        "--output", "-o",
        default="logs/",
        help="Output directory for generated CloudTrail logs (default: logs/)",
    )
    parser.add_argument(
        "--dry-run", "-d",
        action="store_true",
        default=True,
        help="Generate synthetic logs without making real AWS API calls (default: True)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Execute real AWS API calls (requires valid credentials)",
    )
    parser.add_argument(
        "--mutate", "-m",
        action="store_true",
        help="Enable mutation engine for evasion variant generation",
    )
    parser.add_argument(
        "--rounds", "-r",
        type=int,
        default=5,
        help="Number of mutation rounds per template (default: 5)",
    )
    parser.add_argument(
        "--var",
        action="append",
        help="Override a template variable: --var key=value",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List discovered templates without executing them",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Parse variable overrides
    overrides = {}
    if args.var:
        for v in args.var:
            if "=" in v:
                key, value = v.split("=", 1)
                overrides[key.strip()] = value.strip()

    # Discover templates
    templates = discover_templates(args.templates)
    if not templates:
        print(f"❌ No templates found at: {args.templates}")
        sys.exit(1)

    print(f"\n🔍 Discovered {len(templates)} Nuclei template(s):")
    for t in templates:
        print(f"   • {t.relative_to(Path(args.templates).parent)}")

    if args.list:
        # List mode: show template details and exit
        for t in templates:
            try:
                tmpl = load_template(t)
                info = tmpl.get("info", {})
                print(f"\n{'─'*50}")
                print(f"  ID:       {tmpl.get('id')}")
                print(f"  Name:     {info.get('name')}")
                print(f"  Severity: {info.get('severity')}")
                print(f"  Tags:     {info.get('tags')}")
                mitre = info.get("metadata", {}).get("mitre_attack", {})
                if mitre:
                    print(f"  MITRE:    {mitre.get('technique')}")
            except Exception as e:
                print(f"  ⚠️  Error loading {t}: {e}")
        return

    # Execute templates
    dry_run = not args.live
    all_results = []

    print(f"\n🚀 Executing templates ({'DRY-RUN' if dry_run else 'LIVE'} mode)...\n")

    for template_path in templates:
        try:
            template = load_template(template_path)
        except Exception as e:
            print(f"  ⚠️  Skipping {template_path}: {e}")
            continue

        # Apply variable overrides
        if overrides:
            if "variables" not in template:
                template["variables"] = {}
            template["variables"].update(overrides)

        # Run base template
        result = run_template(template, dry_run=dry_run, verbose=args.verbose)
        all_results.append(result)

        # Run mutation variants
        if args.mutate:
            print(f"\n  🧬 Generating {args.rounds} mutation variants...")
            for round_num in range(1, args.rounds + 1):
                mutated = generate_mutation(template, round_num)
                mut_result = run_template(
                    mutated, dry_run=dry_run, verbose=args.verbose
                )
                all_results.append(mut_result)

    # Write results
    written = write_results(all_results, args.output, verbose=args.verbose)

    # Print final summary
    total_events = sum(r["events_generated"] for r in all_results)
    triggered = sum(
        1 for r in all_results
        for m in r["matcher_results"]
        if m["triggered"]
    )
    total_matchers = sum(len(r["matcher_results"]) for r in all_results)

    print(f"\n{'='*70}")
    print(f"  📊 SIMULATION COMPLETE")
    print(f"{'='*70}")
    print(f"  Templates executed:  {len(templates)}")
    print(f"  Total runs:          {len(all_results)} (incl. mutations)")
    print(f"  Events generated:    {total_events}")
    print(f"  Matchers triggered:  {triggered}/{total_matchers}")
    print(f"  Output files:        {len(written)}")
    for f in written:
        print(f"    → {f}")
    print()


if __name__ == "__main__":
    main()
