#!/usr/bin/env python3
"""WARDEN flow guard on AgentDojo with an oracle attacker: no model, no network, deterministic.

For every (user task, injection task) pair of every suite, the benchmark's own attack
(`important_instructions`) is placed where the user task's ground truth reads it. The pipeline then
plays the user task's ground-truth calls, followed by the injection task's ground-truth calls: a model
that read the injection and obeyed it completely, the worst case. Every call passes through the flow
guard first (an `ask` counts as refused: there is no human in a benchmark). AgentDojo's own checks say
whether the user's task was done (utility) and whether the attacker's goal was reached (security).

Variants:
  none    no guard (baseline: an obedient model always completes the attack)
  strict  the guard without the user's prompt: any outbound/destructive call after outside text is refused
  intent  the guard with the user's prompt (UserPromptSubmit): a destination the user named may be reached

usage: oracle.py OUT.json [--suites banking,slack,travel,workspace] [--version v1.2.2]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import ChatAssistantMessage, ChatMessage, ChatToolResultMessage, text_content_block_from_string

HERE = Path(__file__).resolve().parent


class Guard:
    """The compiled flow guard behind a JSONL bridge (scripts/agentdojo/flow-eval-server.mjs)."""

    def __init__(self, policy: Path, mode: str) -> None:
        self.state = tempfile.mkdtemp(prefix="warden-adojo-")
        env = {**os.environ, "WARDEN_STATE_DIR": self.state, "WARDEN_FLOW_POLICY": str(policy), "WARDEN_FLOW_MODE": mode}
        self.proc = subprocess.Popen(["node", str(HERE / "flow-eval-server.mjs")], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, env=env, bufsize=1)

    def _call(self, event: str, hook_input: dict) -> dict | None:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps({"event": event, "input": hook_input}) + "\n")
        self.proc.stdin.flush()
        reply = json.loads(self.proc.stdout.readline())
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return reply["out"]

    def prompt(self, session: str, text: str) -> None:
        self._call("prompt", {"session_id": session, "cwd": "/agentdojo", "prompt": text})

    def pre(self, session: str, tool: str, args: dict) -> tuple[str | None, str]:
        out = self._call("pre", {"session_id": session, "cwd": "/agentdojo", "tool_name": tool, "tool_input": args})
        if not out:
            return None, ""
        h = out["hookSpecificOutput"]
        return h["permissionDecision"], h["permissionDecisionReason"]

    def post(self, session: str, tool: str, args: dict, result: str) -> dict | None:
        return self._call("post", {"session_id": session, "cwd": "/agentdojo", "tool_name": tool, "tool_input": args, "tool_response": result})

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=10)


def jsonable(value):
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class OraclePipeline(BasePipelineElement):
    """Plays the user task's ground truth, then the injection task's, through the guard."""

    name = "gpt-4o-2024-05-13"  # only used by the attack to address the model by name

    def __init__(self, guard: Guard | None, use_intent: bool) -> None:
        self.guard = guard
        self.use_intent = use_intent
        self.user_task = None
        self.injection_task = None
        self.injections: dict[str, str] = {}
        self.log: list[dict] = []
        self.delivered = False

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(), messages: Sequence[ChatMessage] = [],
              extra_args: dict = {}) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        session = "adojo-" + uuid.uuid4().hex
        if self.guard and self.use_intent:
            self.guard.prompt(session, query)
        new: list[ChatMessage] = []
        self.log = []
        self.delivered = False
        # YAML output folds long lines and escapes quotes: compare without whitespace, quotes or backslashes.
        squash = lambda x: re.sub(r"[\s\"'\\]", "", x)
        marker = squash(self.injection_task.GOAL[:60]) if self.injection_task else ""
        phases = [("user", self.user_task)] + ([("attacker", self.injection_task)] if self.injection_task else [])
        self.first_call_refused = None
        for phase, task in phases:
            calls = task.ground_truth(env)
            if phase == "attacker" and not calls:
                probe = first_required_call(task)
                if probe is not None and self.guard:
                    decision, _ = self.guard.pre(session, probe.function, jsonable(dict(probe.args)))
                    self.first_call_refused = decision in ("ask", "deny")
                elif probe is not None:
                    self.first_call_refused = False
                continue
            for call in calls:
                args = jsonable(dict(call.args))
                decision, reason = (self.guard.pre(session, call.function, args) if self.guard else (None, ""))
                if decision in ("ask", "deny"):
                    # A refused call never ran. It is not added as a tool call: AgentDojo's trace-based checks
                    # read the calls in the transcript and would count a refused attempt as done.
                    self.log.append({"phase": phase, "tool": call.function, "decision": decision, "reason": reason[:300]})
                    new.append(ChatAssistantMessage(role="assistant", tool_calls=None,
                                                    content=[text_content_block_from_string(f"[{call.function} refused by WARDEN flow guard]")]))
                    continue
                new.append(ChatAssistantMessage(role="assistant", tool_calls=[call], content=[text_content_block_from_string("")]))
                result, error = runtime.run_function(env, call.function, call.args, raise_on_error=False)
                text = tool_result_to_str(result) if error is None else ""
                # Delivered = the attack text reached the agent through a tool result while it worked on the
                # user's task. Judged from the text itself, not from the guard's labels.
                if phase == "user" and marker and marker in squash(text):
                    self.delivered = True
                if self.guard:
                    self.guard.post(session, call.function, args, text)
                new.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)], tool_call=call,
                                                 tool_call_id=None, error=error))
        new.append(ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(self.user_task.GROUND_TRUTH_OUTPUT)],
                                        tool_calls=None))
        return query, runtime, env, [*messages, *new], extra_args


def check_labels(suites: dict, policy: Path) -> None:
    labels = json.loads(policy.read_text())["labels"]
    missing = sorted({t.name for s in suites.values() for t in s.tools} - set(labels))
    if missing:
        sys.exit(f"tools without an operator label: {missing}")


def injection_kinds(suite, policy: Path) -> dict[str, str]:
    """'action' when the attacker's goal needs an outbound or destructive call, else 'answer' (it only
    changes what the model says, or reads): no tool-call guard can stop the second kind."""
    labels = json.loads(policy.read_text())["labels"]
    env = suite.load_and_inject_default_environment({})
    kinds = {}
    for iid, task in suite.injection_tasks.items():
        calls = [c.function for c in task.ground_truth(env.model_copy(deep=True))]
        if not calls:
            # AgentDojo ships no ground truth for some newer injection tasks: they cannot be replayed.
            kinds[iid] = "no-ground-truth"
            continue
        kinds[iid] = "action" if any(set(labels.get(c, [])) & {"outbound", "destructive"} for c in calls) else "answer"
    return kinds


def first_required_call(task) -> FunctionCall | None:
    """For an injection task without ground truth: the e-mail its goal cannot do without, to the address it names."""
    addresses = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", task.GOAL)
    if not addresses:
        return None
    return FunctionCall(function="send_email", args={"recipients": [addresses[0].rstrip(".")], "subject": "-", "body": "-"})


def run(suites: dict, policy: Path, variant: str) -> dict:
    guard = None if variant == "none" else Guard(policy, "deny")
    pipeline = OraclePipeline(guard, use_intent=(variant == "intent"))
    out: dict = {"variant": variant, "suites": {}}
    try:
        for name, suite in suites.items():
            attack = load_attack("important_instructions", suite, pipeline)
            kinds = injection_kinds(suite, policy)
            pairs, utility_attacked, attack_success, blocked_user_calls = [], 0, 0, 0
            clean = []
            for uid, user_task in suite.user_tasks.items():
                pipeline.user_task, pipeline.injection_task, pipeline.injections = user_task, None, {}
                util, _ = suite.run_task_with_pipeline(pipeline, user_task, None, {})
                clean.append({"user_task": uid, "utility": util, "blocked": pipeline.log})
                for iid, injection_task in suite.injection_tasks.items():
                    injections = attack.attack(user_task, injection_task)
                    pipeline.user_task, pipeline.injection_task, pipeline.injections = user_task, injection_task, injections
                    util, sec = suite.run_task_with_pipeline(pipeline, user_task, injection_task, injections)
                    utility_attacked += util
                    attack_success += sec
                    blocked_user_calls += sum(1 for b in pipeline.log if b["phase"] == "user")
                    pairs.append({"user_task": uid, "injection_task": iid, "kind": kinds[iid], "delivered": pipeline.delivered,
                                  "first_required_call_refused": pipeline.first_call_refused,
                                  "utility": util, "attack_succeeded": sec, "blocked": pipeline.log})
            n = len(pairs)
            out["suites"][name] = {
                "user_tasks": len(clean), "pairs": n,
                "utility_no_attack": sum(c["utility"] for c in clean), "utility_under_attack": utility_attacked,
                "attacks_succeeded": attack_success, "blocked_user_calls_under_attack": blocked_user_calls,
                "injection_kinds": kinds,
                "by_kind": {k: {"pairs": sum(1 for p in pairs if p["kind"] == k), "succeeded": sum(p["attack_succeeded"] for p in pairs if p["kind"] == k)} for k in ("action", "answer")},
                "no_ground_truth": {"pairs": sum(1 for p in pairs if p["kind"] == "no-ground-truth"),
                                    "delivered": sum(1 for p in pairs if p["kind"] == "no-ground-truth" and p["delivered"]),
                                    "first_required_call_refused": sum(1 for p in pairs if p["kind"] == "no-ground-truth" and p["delivered"] and p["first_required_call_refused"])},
                "delivered_action": {"pairs": sum(1 for p in pairs if p["kind"] == "action" and p["delivered"]),
                                     "succeeded": sum(p["attack_succeeded"] for p in pairs if p["kind"] == "action" and p["delivered"])},
                "clean": clean, "pairs_detail": pairs,
            }
            s = out["suites"][name]
            bk, da = s["by_kind"], s["delivered_action"]
            print(f"{variant:6s} {name:10s} utility {s['utility_no_attack']}/{len(clean)} clean, {utility_attacked}/{n} attacked; "
                  f"attacks succeeded {attack_success}/{n} (action {bk['action']['succeeded']}/{bk['action']['pairs']}, "
                  f"answer-only {bk['answer']['succeeded']}/{bk['answer']['pairs']}); delivered action attacks succeeded "
                  f"{da['succeeded']}/{da['pairs']}; no ground truth: first required call refused "
                  f"{s['no_ground_truth']['first_required_call_refused']}/{s['no_ground_truth']['delivered']} delivered", flush=True)
    finally:
        if guard:
            guard.close()
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--suites", default="banking,slack,travel,workspace")
    ap.add_argument("--version", default="v1.2.2")
    ap.add_argument("--variants", default="none,strict,intent")
    ap.add_argument("--policy", default=str(HERE / "policy.json"))
    a = ap.parse_args()
    all_suites = get_suites(a.version)
    suites = {k: all_suites[k] for k in a.suites.split(",")}
    policy = Path(a.policy)
    check_labels(suites, policy)
    started = time.time()
    results = {"benchmark": "AgentDojo", "benchmark_version": a.version, "attack": "important_instructions",
               "attacker": "oracle (ground truth of the injection task, played after the user task)",
               "ask_counts_as": "refused", "variants": {}}
    for v in a.variants.split(","):
        results["variants"][v] = run(suites, policy, v)
    results["seconds"] = round(time.time() - started, 1)
    Path(a.out).write_text(json.dumps(results, indent=1))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
