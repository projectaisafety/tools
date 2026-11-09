#!/usr/bin/env python3
"""Run an AI Safety Compliance Lab test from a script or CI pipeline, and save the signed evidence.

    export AISL_TOKEN=aisl_...            # API token from the dashboard (optional, but needed in CI)
    export MODEL_API_KEY=sk-...           # the key for the model you are testing
    python aisl_run.py --provider openai --model gpt-6-luna --suite default_15 --strength standard

Starts the run, prints status lines while it goes, saves the evidence file, prints the verdict and
exits with a code your pipeline can act on:

    0  the verdict is acceptable under --fail-on
    1  the verdict is not acceptable (by default: FAILED), so the build should fail
    2  the run gave no complete answer: an error, a cancelled run, or an INCOMPLETE verdict
       (some tests could not be graded). Treat it as a failed check, never as a pass.

Baseline mode (--baseline FILE): fail only on NEW failures. FILE is the evidence file of an earlier run
you have accepted, for example committed to your repository as ai-safety-baseline.json. A test that
already failed in the baseline does not fail the check again; a test that passed there (or is new)
and fails now does. With --fail-on review, a new WARN also fails it. The baseline is checked before it
is used: its record must match its hash and carry a valid signature from the server you run against.
--write-baseline PATH saves this run's evidence as the new baseline when the check passes.

Press Ctrl+C to cancel the run: tests already finished are kept, and the evidence is still saved.
Your model key is sent only to the platform for this run, which never stores it. Needs Python 3.9+
and nothing else. In GitHub Actions the verdict is also written to the job summary.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import shutil
import time
import urllib.error
import urllib.request

STRENGTHS = {   # same presets as the dashboard's Test strength
    "quick": ("inspect_ai", 1, "standard"),
    "standard": ("sequential", 3, "standard"),
    "deep": ("sequential", 3, "full"),
    "maximum": ("sequential", 5, "adaptive"),
}
# Default grader, as on the dashboard: the strongest model from the target's own provider that is not
# the model under test (same provider, different model). Use --grader-provider for a different provider.
# Keep the first model of each in step with static/model_catalog.json (tests/test_model_catalog.py checks).
DEFAULT_GRADERS = {
    "openai": ["gpt-6-sol", "gpt-5.6-sol", "gpt-6-luna"],
    "google": ["gemini-3.8-flash", "gemini-3.6-flash"],
    "mistral": ["mistral-large-latest", "mistral-medium-latest"],
    "deepseek": ["deepseek-v4-pro", "deepseek-v4-flash"],
    "alibaba": ["qwen3.8-max", "qwen3.8-flash"],
    "groq": ["openai/gpt-oss-120b", "llama-3.3-70b-versatile"],
    "anthropic": ["claude-opus-5-5", "claude-sonnet-5-5"],
    "moonshot": ["kimi-k3.1-pro", "kimi-k3"],
    "minimax": ["MiniMax-M3", "MiniMax-M2.7"],
    "baidu": ["ernie-5.1"],
}
FAIL_ON = {
    "failed": {"FAILED"},
    "review": {"FAILED", "REVIEW REQUIRED"},
}


def call(base: str, path: str, token: str | None, body: dict | None = None, timeout: int = 60):
    req = urllib.request.Request(base.rstrip("/") + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", "User-Agent": "aisl-run/1"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            detail = json.load(e).get("detail")
        except Exception:  # noqa: BLE001
            detail = None
        return e.code, {"detail": detail or e.reason}


GRADED = ("PASSED", "WARN", "FAILED")


def load_baseline(path: str, base_url: str, token: str | None) -> dict:
    """The baseline's signed record, after checking it. Raises ValueError with a plain reason."""
    try:
        with open(path, encoding="utf-8-sig") as f:
            doc = json.load(f)
    except OSError as e:
        raise ValueError(f"cannot read {path}: {e.strerror or e}") from None
    except ValueError:
        raise ValueError(f"{path} is not an evidence file (not JSON)") from None
    run = doc.get("data", doc) if isinstance(doc, dict) else {}
    canonical = run.get("hashed_record_json")
    if not isinstance(canonical, str):
        raise ValueError(f"{path} has no signed record (an older, unsigned format)")
    if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != run.get("artifact_hash"):
        raise ValueError(f"{path} was changed after its run: the record does not match its hash")
    # The signature is checked by the server you run against, so this script needs no libraries.
    status, view = call(base_url, "/api/v1/evidence/check", token, {"data": run})
    if status != 200 or not view.get("valid"):
        raise ValueError(f"{path} could not be used as a baseline: {view.get('detail') or 'its signature is not valid'}")
    return json.loads(canonical)


def baseline_changes(base: dict, now: dict, fail_on: str) -> dict:
    """Compare two signed records test by test. New failures are what fails the check."""
    before = {str(v.get("id")): v.get("status") for v in base.get("vectors") or []}
    out = {"new_failures": [], "new_warnings": [], "known": [], "fixed": [], "new_tests": 0, "setup": []}
    for v in now.get("vectors") or []:
        tid, st = str(v.get("id")), v.get("status")
        was = before.get(tid)
        if was is None:
            out["new_tests"] += 1
        if st == "FAILED":
            (out["known"] if was == "FAILED" else out["new_failures"]).append((v, was))
        elif st == "WARN":
            if was in ("WARN", "FAILED"):
                out["known"].append((v, was))
            elif fail_on == "review":
                out["new_warnings"].append((v, was))
        elif st == "PASSED" and was in ("WARN", "FAILED"):
            out["fixed"].append((v, was))
    for key, label in (("target_model", "model"), ("suite_id", "suite"), ("engine", "engines"),
                       ("runs_per_vector", "runs per test"), ("attack_depth", "attack depth"),
                       ("grader_model", "grader")):
        if (base.get(key) or None) != (now.get(key) or None):
            out["setup"].append(f"{label} {base.get(key)} -> {now.get(key)}")
    if json.dumps(base.get("system_prompt"), sort_keys=True) != json.dumps(now.get("system_prompt"), sort_keys=True):
        out["setup"].append("system prompt changed")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("AISL_URL", "https://projectaisafety.com"))
    ap.add_argument("--provider", required=True, help="openai, anthropic, google, mistral, groq, deepseek, alibaba, moonshot, minimax, baidu, custom or app")
    ap.add_argument("--model", required=True, help="model id, or your endpoint's HTTPS address for custom/app")
    ap.add_argument("--suite", default="default_15", help="test suite id (default: default_15)")
    ap.add_argument("--strength", choices=STRENGTHS, default="standard")
    ap.add_argument("--engine", choices=["inspect_ai", "pyrit", "sequential"], help="overrides --strength")
    ap.add_argument("--runs", type=int, choices=range(1, 6), help="overrides --strength")
    ap.add_argument("--attack-depth", choices=["standard", "extended", "full", "adaptive"], help="overrides --strength")
    ap.add_argument("--grader-model", help="grader model id (default: as on the dashboard, the strongest other model from your provider)")
    ap.add_argument("--grader-provider", help="grade with a different provider; its key goes in GRADER_API_KEY")
    ap.add_argument("--system-prompt-file", help="file with your production system prompt")
    ap.add_argument("--system-prompt-mode", choices=["replace", "add"], default="replace",
                    help="replace each test's own role with the file (your full product prompt, the default), "
                         "or add it after that role (to re-test a report's suggested fixes)")
    ap.add_argument("--endpoint-model", help="custom endpoint only: the model name it serves")
    ap.add_argument("--authorised", action="store_true", help="custom endpoint or app: you own it or may test it")
    ap.add_argument("--framework", default="eu_ai_act", choices=["eu_ai_act", "owasp_llm", "nist_rmf", "iso_42001"])
    ap.add_argument("--fail-on", choices=FAIL_ON, default="failed",
                    help="failed: fail the check on FAILED (default); review: also on REVIEW REQUIRED")
    ap.add_argument("--baseline", help="evidence file of an accepted earlier run: fail only on new failures")
    ap.add_argument("--write-baseline", metavar="PATH", help="when the check passes, save this run's evidence here as the next baseline")
    ap.add_argument("--out", help="where to save the evidence file (default: ai-safety-run-<id>.json)")
    ap.add_argument("--key-env", default="MODEL_API_KEY", help="environment variable holding the model key")
    a = ap.parse_args()

    token = os.environ.get("AISL_TOKEN") or None
    if token:
        # The id is not secret: it cannot start runs or withdraw the token. It is printed so each CI
        # run can be matched to its token; withdrawal needs the token or its emailed withdrawal link.
        try:
            part = token.strip()[len("aisl_"):].split(".")[0]
            info = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            print(f"API token id: {info['id']}" + (f" ({info['label']})" if info.get("label") else ""), flush=True)
        except (ValueError, KeyError, TypeError):
            pass
    key = os.environ.get(a.key_env)
    if not key:
        print(f"Set {a.key_env} to the API key for the model you are testing.", file=sys.stderr)
        return 2
    baseline = None
    if a.baseline:
        try:
            baseline = load_baseline(a.baseline, a.url, token)
        except ValueError as e:
            print(f"Baseline not used: {e}.", file=sys.stderr)
            return 2
        print(f"Baseline: {a.baseline} (run {str(baseline.get('run_id', ''))[:8]}, {baseline.get('timestamp')}, "
              f"{baseline.get('status')}; signature checked). Only new failures fail this check.", flush=True)
    engine, runs, depth = STRENGTHS[a.strength]
    payload = {"target_model": a.model, "model_provider": a.provider, "client_api_key": key, "suite_id": a.suite,
               "engine": a.engine or engine, "runs": a.runs or runs, "attack_depth": a.attack_depth or depth,
               "framework": a.framework, "authorised": a.authorised}
    grader = a.grader_model
    if not grader and not a.grader_provider:
        grader = next((m for m in DEFAULT_GRADERS.get(a.provider, []) if m.lower() != a.model.lower()), None)
        if grader:
            print(f"Grader: {grader} (same provider, different model). Choose another with --grader-model.", flush=True)
        else:
            print("Choose a grader: the model under test never grades its own answers. Use --grader-model for "
                  "another model from your provider, or --grader-provider with GRADER_API_KEY.", file=sys.stderr)
            return 2
    if a.grader_provider and not grader:
        grader = (DEFAULT_GRADERS.get(a.grader_provider) or [None])[0]
        if not grader:
            print("Give --grader-model for that grader provider.", file=sys.stderr)
            return 2
    if grader:
        payload["grader_model"] = grader
    if a.grader_provider:
        payload["grader_provider"] = a.grader_provider
        payload["grader_api_key"] = os.environ.get("GRADER_API_KEY")
        if not payload["grader_api_key"]:
            print("Set GRADER_API_KEY for the grader's provider.", file=sys.stderr)
            return 2
    if a.system_prompt_file:
        with open(a.system_prompt_file, encoding="utf-8") as f:
            payload["system_prompt"] = f.read()
        payload["system_prompt_mode"] = a.system_prompt_mode
    if a.endpoint_model:
        payload["endpoint_model"] = a.endpoint_model

    status, view = call(a.url, "/api/v1/jobs", token, payload)
    if status != 200:
        print(f"The run was not started: {view.get('detail')}", file=sys.stderr)
        return 2
    jid = view["job_id"]
    print(f"Run started ({a.provider} {a.model}, suite {a.suite}, {payload['engine']}, {payload['runs']} run(s), "
          f"attack depth {payload['attack_depth']}). Press Ctrl+C to cancel and keep what has finished.", flush=True)

    log_from, last_stage, cancelled, failures = 0, None, False, 0
    while True:
        try:
            status, view = call(a.url, f"/api/v1/jobs/{jid}?log_from={log_from}", token)
            if status != 200:
                print(f"The run is no longer available: {view.get('detail')}", file=sys.stderr)
                return 2
            failures = 0
            for line in (view.get("log") or {}).get("lines", []):
                print("  " + line, flush=True)
            log_from = (view.get("log") or {}).get("next", log_from)
            if view.get("stage") != last_stage and not (view.get("log") or {}).get("lines"):
                print("  " + str(view.get("stage")), flush=True)
            last_stage = view.get("stage")
            if view["status"] in ("done", "error", "cancelled"):
                break
            time.sleep(5)
        except KeyboardInterrupt:
            if cancelled:
                print("Stopped waiting. The run may still finish on the server.", file=sys.stderr)
                return 2
            cancelled = True
            print("\nCancelling: finished tests are kept. Press Ctrl+C again to stop waiting.", flush=True)
            call(a.url, f"/api/v1/jobs/{jid}/cancel", token, {})
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            failures += 1
            if failures > 24:
                print(f"Lost contact with the server ({e}). The run continues there.", file=sys.stderr)
                return 2
            time.sleep(5)

    if view["status"] != "done":
        print(f"The run ended without a result: {view.get('error')}", file=sys.stderr)
        return 2
    status, evidence = call(a.url, f"/api/v1/jobs/{jid}/evidence", token)
    if status != 200:
        print(f"Could not download the evidence: {evidence.get('detail')}", file=sys.stderr)
        return 2
    d = evidence["data"]
    out = a.out or f"ai-safety-run-{str(d.get('run_id', jid))[:8]}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    verdict = d.get("status")
    vs = d.get("vectors_evaluated") or []
    not_passed = [v for v in vs if v.get("status") != "PASSED"]
    score = d.get("safety_score")
    ts = d.get("trusted_timestamp") or {}
    print(f"\nVerdict: {verdict}  ·  {sum(v.get('status') == 'PASSED' for v in vs)} of {len(vs)} tests passed"
          + (f"  ·  pass rate {score * 100:.1f}%" if isinstance(score, (int, float)) else ""))
    for v in not_passed:
        print(f"  {v.get('status'):8} {v.get('id')}  {v.get('name')}  [{v.get('severity') or '-'}]")
    print(f"Evidence: {out}  (SHA-256 {d.get('artifact_hash')}"
          + (", signed" if (d.get("signature") or {}).get("signature_b64") else ", not signed")
          + (f", timestamped {ts.get('gen_time')}" if ts.get("status") == "timestamped" else "") + ")")
    print("Verify it: python verify_evidence.py " + out + "   or   https://projectaisafety.com/static/verify.html")

    changes = None
    if baseline is not None:
        changes = baseline_changes(baseline, json.loads(d["hashed_record_json"]), a.fail_on)
        print(f"\nCompared with the baseline: {len(changes['new_failures'])} new failure(s)"
              + (f", {len(changes['new_warnings'])} new warning(s)" if a.fail_on == "review" else "")
              + f", {len(changes['known'])} already in the baseline, {len(changes['fixed'])} fixed"
              + (f", {changes['new_tests']} test(s) not in the baseline" if changes["new_tests"] else "") + ".")
        for label, rows in (("NEW", changes["new_failures"] + changes["new_warnings"]), ("known", changes["known"]),
                            ("fixed", changes["fixed"])):
            for v, was in rows:
                print(f"  {label:6} {v.get('id')}  {was or 'not in baseline'} -> {v.get('status')}  {v.get('name')}")
        if changes["setup"]:
            print("  Note: this run was not set up like the baseline, so some changes may come from the setup: "
                  + "; ".join(changes["setup"]) + ".")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"## AI safety test: {verdict}\n\n{a.provider} `{a.model}` · suite `{a.suite}` · "
                    f"{sum(v.get('status') == 'PASSED' for v in vs)} of {len(vs)} tests passed\n\n")
            if changes is not None:
                f.write(f"Compared with the baseline `{a.baseline}`: **{len(changes['new_failures']) + len(changes['new_warnings'])} new**, "
                        f"{len(changes['known'])} already known, {len(changes['fixed'])} fixed.\n\n")
                rows = [("NEW", v, w) for v, w in changes["new_failures"] + changes["new_warnings"]] \
                    + [("known", v, w) for v, w in changes["known"]] + [("fixed", v, w) for v, w in changes["fixed"]]
                if rows:
                    f.write("| Change | Test | Baseline → now | Severity |\n|---|---|---|---|\n")
                    for tag, v, w in rows:
                        f.write(f"| {tag} | {v.get('id')} {v.get('name')} | {w or 'not in baseline'} → {v.get('status')} | {v.get('severity') or '-'} |\n")
                if changes["setup"]:
                    f.write("\nSet up differently from the baseline: " + "; ".join(changes["setup"]) + "\n")
            elif not_passed:
                f.write("| Result | Test | Severity |\n|---|---|---|\n")
                for v in not_passed:
                    f.write(f"| {v.get('status')} | {v.get('id')} {v.get('name')} | {v.get('severity') or '-'} |\n")
            f.write(f"\nEvidence file `{out}` · SHA-256 `{d.get('artifact_hash')}`\n")

    incomplete = bool(d.get("cancelled")) or verdict in ("INCOMPLETE", "UNGRADED")
    if changes is not None:
        new = len(changes["new_failures"]) + len(changes["new_warnings"])
        if new:
            print(f"FAIL: {new} new failure(s) compared with the baseline (--fail-on {a.fail_on})")
            return 1
        if incomplete:
            print(f"NOT COMPLETE: verdict {verdict}" + (" (cancelled)" if d.get("cancelled") else "")
                  + ". Some tests have no result, so this run cannot pass a check.")
            return 2
        print(f"OK: no new failures compared with the baseline (verdict {verdict})")
    else:
        if verdict in FAIL_ON[a.fail_on]:
            print(f"FAIL: verdict {verdict} (--fail-on {a.fail_on})")
            return 1
        if incomplete:
            print(f"NOT COMPLETE: verdict {verdict}" + (" (cancelled)" if d.get("cancelled") else "")
                  + ". Some tests have no result, so this run cannot pass a check.")
            return 2
        print(f"OK: verdict {verdict} (--fail-on {a.fail_on})")
    if a.write_baseline:
        shutil.copyfile(out, a.write_baseline)
        print(f"Saved this run as the next baseline: {a.write_baseline}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
