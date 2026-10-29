"""Runtime components extracted from the original Moirae runner."""
import asyncio
import json
import random
import re
import time
from dataclasses import asdict, is_dataclass, replace
from pathlib import Path
from typing import Any
from pydantic import BaseModel
from pydantic_ai import Agent
from ..evidence.tools import AndroidEvidenceDeps, safe_exception_text
from ..config import RunnerConfig, utc_now_iso
from .data import sample_context
from .schemas import APIAgentResult, StageFinding, UIEventAgentResult, VisionAgentResult


async def run_agent_with_retry(
    agent: Agent,
    prompt: str,
    deps: AndroidEvidenceDeps,
    retries: int = 5,
    initial_wait: int = 20,
    retry_audit: dict[str, Any] | None = None,
):
    """Run one logical Agent stage and record every top-level ``agent.run`` attempt.

    ``retries`` is retained for CLI compatibility, but it is the maximum number
    of attempts including the initial attempt. PydanticAI-internal model/tool or
    structured-output retries are not individual entries in ``attempts``; their
    aggregate model-request count is captured from the successful result.
    """
    max_attempts = max(1, int(retries))
    attempts: list[dict[str, Any]] = []
    retry_wait_seconds = 0.0

    def update_retry_audit() -> None:
        if retry_audit is None:
            return
        retry_audit.clear()
        retry_audit.update(
            {
                "configured_max_attempts": max_attempts,
                "attempt_count": len(attempts),
                "retry_count": max(len(attempts) - 1, 0),
                "retry_wait_seconds": round(retry_wait_seconds, 3),
                "attempts": list(attempts),
            }
        )

    for attempt_index in range(1, max_attempts + 1):
        attempt_started_at_utc = utc_now_iso()
        attempt_started = time.perf_counter()
        try:
            result = await agent.run(prompt, deps=deps)
            attempts.append(
                {
                    "attempt_index": attempt_index,
                    "status": "success",
                    "started_at_utc": attempt_started_at_utc,
                    "finished_at_utc": utc_now_iso(),
                    "duration_seconds": round(time.perf_counter() - attempt_started, 3),
                    "retryable_error": False,
                    "scheduled_retry_wait_seconds": 0.0,
                }
            )
            update_retry_audit()
            return result
        except Exception as exc:
            error_text = str(exc).lower()
            retryable = any(marker in error_text for marker in ("429", "rate limit", "rejected"))
            can_retry = retryable and attempt_index < max_attempts
            wait_time = 0.0
            if can_retry:
                response = getattr(exc, "response", None)
                headers = getattr(response, "headers", None)
                retry_after = headers.get("retry-after") if headers else None
                if retry_after:
                    try:
                        wait_time = float(retry_after) + 2.0
                    except ValueError:
                        wait_time = 0.0
                if wait_time <= 0:
                    wait_time = (initial_wait * (2 ** (attempt_index - 1))) + random.uniform(3, 10)

            attempts.append(
                {
                    "attempt_index": attempt_index,
                    "status": "failed",
                    "started_at_utc": attempt_started_at_utc,
                    "finished_at_utc": utc_now_iso(),
                    "duration_seconds": round(time.perf_counter() - attempt_started, 3),
                    "retryable_error": retryable,
                    "error": safe_exception_text(exc, "Agent attempt failed"),
                    "scheduled_retry_wait_seconds": round(wait_time, 3),
                }
            )
            update_retry_audit()

            if not can_retry:
                raise

            print(
                f"[RateLimit] Waiting {wait_time:.1f}s before "
                f"attempt {attempt_index + 1}/{max_attempts}."
            )
            await asyncio.sleep(wait_time)
            retry_wait_seconds += wait_time
            update_retry_audit()

    raise RuntimeError(f"Agent failed after {max_attempts} attempts.")


def extract_json_text(text: str) -> str:
    text = str(text)
    match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        return match.group(1).strip()

    match = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        candidate = match.group(1).strip()
        if candidate.startswith("{"):
            return candidate

    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1:
        return text[start : end + 1]
    return text


def serialize_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return f"<bytes length={len(value)}>"
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): serialize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [serialize_value(item) for item in value]
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump(mode="json")
        except TypeError:
            return value.model_dump()
    if is_dataclass(value):
        return serialize_value(asdict(value))
    return str(value)


def agent_result_output(result: Any) -> Any:
    for attr in ("output", "data", "return_value"):
        if hasattr(result, attr):
            value = getattr(result, attr)
            if value is not None:
                return value
    return result


def result_text(result: Any) -> str:
    output = agent_result_output(result)
    if output is not result:
        if hasattr(output, "model_dump_json"):
            try:
                return output.model_dump_json(indent=2, by_alias=True)
            except TypeError:
                return output.model_dump_json(indent=2)
        if isinstance(output, (dict, list)):
            return json.dumps(output, indent=2, ensure_ascii=False)
        return str(output)

    if isinstance(result, str):
        return result
    return str(result)


def model_from_result(result: Any, model_type: type[BaseModel]) -> BaseModel:
    output = agent_result_output(result)
    if isinstance(output, model_type):
        return output
    if isinstance(output, BaseModel):
        return model_type.model_validate(output.model_dump(mode="json", by_alias=True))
    if isinstance(output, dict):
        return model_type.model_validate(output)
    return model_type.model_validate_json(extract_json_text(str(output)))


def normalize_final_report_apk_name(final_report: dict[str, Any] | None, sample_hash: str) -> dict[str, Any] | None:
    if final_report is not None:
        final_report["apk_name"] = sample_hash
    return final_report


def public_final_report(
    report: dict[str, Any] | None,
    sample_hash: str,
    source_index: int,
    status: str,
) -> dict[str, Any]:
    """Return the fixed, minimal schema written to analysis_reports.json."""
    report = report if isinstance(report, dict) else {}
    error = str(report.get("error") or "Final Judge result is unavailable.")
    evidence_chain = report.get("evidence_chain")
    if not isinstance(evidence_chain, list):
        evidence_chain = [f"1. [Analysis Failure] {error}"] if status != "success" else []
    return {
        "apk_name": sample_hash,
        "is_malicious": report.get("is_malicious"),
        "threat_category(Malicious family)": (
            report.get("threat_category(Malicious family)")
            or report.get("threat_category")
            or "Unknown"
        ),
        "confidence_score": report.get("confidence_score", 0),
        "reason": report.get("reason") or error,
        "evidence_chain": evidence_chain,
        "source_index": source_index,
        "status": status,
    }


def result_method_value(result: Any, name: str) -> Any:
    value = getattr(result, name, None)
    if value is None:
        return None
    try:
        return serialize_value(value() if callable(value) else value)
    except Exception as exc:  # pragma: no cover
        return {"error": safe_exception_text(exc, f"Could not read {name}")}


def _usage_field(usage: Any, *names: str) -> int | None:
    for name in names:
        value = usage.get(name) if isinstance(usage, dict) else getattr(usage, name, None)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _usage_from_messages(agent_result: Any) -> dict[str, int | None] | None:
    messages_value = getattr(agent_result, "new_messages", None)
    if messages_value is None:
        return None
    try:
        messages = messages_value() if callable(messages_value) else messages_value
    except Exception:
        return None

    input_tokens = 0
    output_tokens = 0
    found_usage = False
    for message in messages or []:
        usage = message.get("usage") if isinstance(message, dict) else getattr(message, "usage", None)
        if usage is None:
            continue
        found_usage = True
        input_tokens += _usage_field(usage, "input_tokens", "request_tokens") or 0
        output_tokens += _usage_field(usage, "output_tokens", "response_tokens") or 0
    if not found_usage:
        return None
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
    }


def extract_token_usage(agent_result: Any) -> dict[str, int | None]:
    unavailable = {
        "input_tokens": None,
        "output_tokens": None,
        "total_tokens": None,
    }
    if agent_result is None:
        return unavailable

    usage_value = getattr(agent_result, "usage", None)
    if usage_value is not None:
        try:
            usage = usage_value() if callable(usage_value) else usage_value
        except Exception:
            usage = None
        if usage is not None:
            input_tokens = _usage_field(usage, "input_tokens", "request_tokens")
            output_tokens = _usage_field(usage, "output_tokens", "response_tokens")
            total_tokens = _usage_field(usage, "total_tokens")
            if total_tokens is None and input_tokens is not None and output_tokens is not None:
                total_tokens = input_tokens + output_tokens
            if input_tokens is not None or output_tokens is not None or total_tokens is not None:
                return {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": total_tokens,
                }

    return _usage_from_messages(agent_result) or unavailable


def extract_model_request_count(agent_result: Any) -> int | None:
    """Return provider model-request count when exposed by PydanticAI usage."""
    if agent_result is None:
        return None
    usage_value = getattr(agent_result, "usage", None)
    if usage_value is not None:
        try:
            usage = usage_value() if callable(usage_value) else usage_value
        except Exception:
            usage = None
        request_count = _usage_field(
            usage,
            "requests",
            "request_count",
            "model_requests",
        )
        if request_count is not None:
            return request_count

    messages_value = getattr(agent_result, "new_messages", None)
    if messages_value is None:
        return None
    try:
        messages = messages_value() if callable(messages_value) else messages_value
    except Exception:
        return None
    # This fallback counts response messages carrying usage. It is intentionally
    # conservative and may be unavailable for providers that omit message usage.
    count = sum(
        1
        for message in messages or []
        if (message.get("usage") if isinstance(message, dict) else getattr(message, "usage", None))
        is not None
    )
    return count or None


def count_tool_calls(messages: Any) -> int:
    """Count tool-call message parts in one successful Agent result."""
    count = 0
    for message in messages or []:
        parts = message.get("parts", []) if isinstance(message, dict) else getattr(message, "parts", [])
        for part in parts or []:
            kind = part.get("part_kind") if isinstance(part, dict) else getattr(part, "part_kind", None)
            if str(kind or "").lower().replace("_", "-") == "tool-call":
                count += 1
    return count


def usage_text(agent_result: Any) -> str:
    usage = extract_token_usage(agent_result)

    def display(value: int | None) -> str:
        return str(value) if value is not None else "N/A"

    return (
        f"Input {display(usage['input_tokens'])} | "
        f"Output {display(usage['output_tokens'])} | "
        f"Total {display(usage['total_tokens'])}"
    )


def markdown_code_block(content: Any, language: str = "text") -> str:
    text = str(content or "").rstrip()
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}{language}\n{text}\n{fence}"


def _part_field(part: Any, name: str, default: Any = None) -> Any:
    if isinstance(part, dict):
        return part.get(name, default)
    return getattr(part, name, default)


def trace_part_payload(part: Any) -> str:
    for field in ("args", "content", "return_value"):
        value = _part_field(part, field)
        if value is not None:
            return json.dumps(serialize_value(value), indent=2, ensure_ascii=False)
    return json.dumps(serialize_value(part), indent=2, ensure_ascii=False)


def _prompt_from_messages(messages: Any) -> str:
    for message in messages if isinstance(messages, list) else []:
        parts = _part_field(message, "parts", []) or []
        for part in parts:
            if _part_field(part, "part_kind") == "user-prompt":
                return str(_part_field(part, "content", ""))
    return ""


def render_agent_trace_markdown(stage_audit: dict[str, Any], heading_level: int = 5) -> str:
    """Render one call from structured audit data; this performs no file I/O."""
    heading_level = min(max(heading_level, 1), 5)
    heading = "#" * heading_level
    subheading = "#" * (heading_level + 1)
    messages = stage_audit.get("new_messages") or []
    prompt = str(stage_audit.get("prompt") or _prompt_from_messages(messages)).strip()
    usage = _stage_token_usage(stage_audit)

    def display(value: Any) -> str:
        return str(value) if value is not None else "N/A"

    status = "failed" if stage_audit.get("error") else str(stage_audit.get("status") or "success")
    lines = [
        f"{heading} {stage_audit.get('stage') or 'Unknown Agent'}",
        "",
        f"- Execution group: `{stage_audit.get('execution_group') or 'unknown'}`",
        f"- Parallel group ID: `{stage_audit.get('parallel_group_id') or 'N/A'}`",
        f"- Status: `{status}`",
        f"- Started (UTC): `{stage_audit.get('started_at_utc') or 'N/A'}`",
        f"- Finished (UTC): `{stage_audit.get('finished_at_utc') or 'N/A'}`",
        f"- Duration: `{float(stage_audit.get('duration_seconds') or 0.0):.3f}s`",
        "- Tokens: "
        f"input `{display(usage.get('input_tokens'))}`, "
        f"output `{display(usage.get('output_tokens'))}`, "
        f"total `{display(usage.get('total_tokens'))}`",
        "",
        f"{subheading} User input",
        "",
        markdown_code_block(prompt, "text"),
    ]

    tool_steps: list[str] = []
    for message_index, message in enumerate(messages if isinstance(messages, list) else [], start=1):
        parts = _part_field(message, "parts", []) or []
        for part in parts:
            part_kind = _part_field(part, "part_kind", "")
            if part_kind not in {"tool-call", "tool-return"}:
                continue
            action = "Call" if part_kind == "tool-call" else "Return"
            tool_name = _part_field(part, "tool_name", "unknown_tool")
            tool_steps.extend(
                [
                    f"**Message {message_index} — {action} `{tool_name}`**",
                    "",
                    markdown_code_block(trace_part_payload(part), "json"),
                    "",
                ]
            )
    if tool_steps:
        lines.extend(["", f"{subheading} Execution trace", "", *tool_steps])

    lines.extend(
        [
            "",
            f"{subheading} Final LLM output",
            "",
            markdown_code_block(stage_audit.get("raw_output") or stage_audit.get("error") or "", "text"),
        ]
    )
    if stage_audit.get("parsed_output") is not None:
        lines.extend(
            [
                "",
                f"{subheading} Parsed structure",
                "",
                markdown_code_block(
                    json.dumps(stage_audit["parsed_output"], indent=2, ensure_ascii=False),
                    "json",
                ),
            ]
        )
    return "\n".join(lines).rstrip()


def model_json(model_obj: BaseModel) -> str:
    return model_obj.model_dump_json(indent=2)


def isolated_agent_deps(deps: AndroidEvidenceDeps) -> AndroidEvidenceDeps:
    """Share read-only evidence while isolating per-agent ReAct bookkeeping."""
    return replace(deps, visited_screens=set(), observation_counter=0)


def stage_failure(stage: str, deps: AndroidEvidenceDeps, exc: Exception) -> BaseModel:
    error = safe_exception_text(exc, f"{stage} execution failed")
    finding = StageFinding(
        label=f"{stage} execution failed",
        severity="unknown",
        evidence=error,
        interpretation="This stage did not produce reliable evidence and must not be used as positive proof.",
    )
    if stage == "Vision Agent":
        return VisionAgentResult(
            sample_hash=deps.sample_hash,
            screens_reviewed=[],
            phishing_or_impersonation_signals=[],
            coercive_or_deceptive_ui_signals=[finding],
            benign_ui_signals=[],
            risk_level="unknown",
            summary=error,
        )
    if stage == "UI/Event Agent":
        return UIEventAgentResult(
            sample_hash=deps.sample_hash,
            screens_or_events_reviewed=[],
            state_event_findings=[finding],
            suspicious_transitions=[],
            permission_or_external_focus_findings=[],
            silent_or_deceptive_trigger_candidates=[],
            risk_level="unknown",
            summary=error,
        )
    return APIAgentResult(
        sample_hash=deps.sample_hash,
        events_reviewed=[],
        api_findings=[finding],
        high_risk_api_calls=[],
        data_leakage_or_abuse_signals=[],
        benign_or_empty_trace_notes=[],
        risk_level="unknown",
        summary=error,
    )


async def run_stage(
    stage_name: str,
    agent: Agent,
    prompt: str,
    deps: AndroidEvidenceDeps,
    output_type: type[BaseModel],
    config: RunnerConfig,
    execution_group: str = "parallel_evidence",
) -> tuple[BaseModel, dict[str, Any]]:
    started_at_utc = utc_now_iso()
    started = time.perf_counter()
    result = None
    retry_audit: dict[str, Any] = {}
    try:
        result = await run_agent_with_retry(
            agent,
            prompt,
            deps=deps,
            retries=config.agent_retries,
            initial_wait=config.retry_initial_wait,
            retry_audit=retry_audit,
        )
        parsed = model_from_result(result, output_type)
        duration = time.perf_counter() - started
        finished_at_utc = utc_now_iso()
        new_messages = result_method_value(result, "new_messages")
        return parsed, {
            "stage": stage_name,
            "execution_group": execution_group,
            "status": "success",
            "started_at_utc": started_at_utc,
            "finished_at_utc": finished_at_utc,
            "duration_seconds": round(duration, 3),
            "token_usage": extract_token_usage(result),
            "model_request_count": extract_model_request_count(result),
            "tool_call_count": count_tool_calls(new_messages),
            "tool_call_count_complete": retry_audit.get("retry_count") == 0,
            "retry_audit": retry_audit,
            "prompt": prompt,
            "new_messages": new_messages,
            "all_messages": result_method_value(result, "all_messages"),
            "raw_output": result_text(result),
            "parsed_output": serialize_value(parsed),
        }
    except Exception as exc:
        duration = time.perf_counter() - started
        finished_at_utc = utc_now_iso()
        fallback = stage_failure(stage_name, deps, exc)
        error = safe_exception_text(exc, f"{stage_name} execution failed")
        return fallback, {
            "stage": stage_name,
            "execution_group": execution_group,
            "status": "failed",
            "started_at_utc": started_at_utc,
            "finished_at_utc": finished_at_utc,
            "duration_seconds": round(duration, 3),
            "token_usage": extract_token_usage(result),
            "model_request_count": extract_model_request_count(result),
            "tool_call_count": 0,
            "tool_call_count_complete": False,
            "retry_audit": retry_audit,
            "prompt": prompt,
            "new_messages": result_method_value(result, "new_messages"),
            "all_messages": result_method_value(result, "all_messages"),
            "raw_output": error,
            "error": error,
            "parsed_output": serialize_value(fallback),
        }


def build_vision_prompt(deps: AndroidEvidenceDeps) -> str:
    return (
        f"{sample_context(deps, include_event_summary=False, include_trace_summary=False)}\n"
        "Task: Independently perform one complete visual ReAct investigation over the whole APK. "
        "Discover and inspect every available screen with your tools. "
        "Inspect for (includes but is not limited to the following types):\n"
        "1. Phishing indicators:\n"
        "   - Fake login/payment/account verification pages\n"
        "   - Brand impersonation or misleading identity\n"
        "   - Requests for credentials, OTP, banking data, or sensitive information\n"
        "2. Fake or deceptive system UI:\n"
        "   - App UI pretending to be Android system dialogs\n"
        "   - Fake permission prompts\n"
        "   - Overlay-style deception\n"
        "3. Forced or induced user actions:\n"
        "   - Misleading buttons\n"
        "   - Hidden decline options\n"
        "   - Urgency/scare tactics\n"
        "4. Benign indicators:\n"
        "   - Normal application flow\n"
        "   - Legitimate Android permission/system dialogs\n\n"
        "Do not make a final summary until the available visual evidence is sufficiently covered. "
        "Use concrete screen_index evidence and explicitly identify any unavailable or uninspected evidence."
    )


def build_ui_event_prompt(deps: AndroidEvidenceDeps) -> str:
    return (
        f"{sample_context(deps, include_trace_summary=False)}\n"
        "Task: Independently perform one complete ReAct investigation of XML/UI states and DroidBot event causality "
        "over the whole APK. Discover and review every available state and related event with your tools. "
        "Inspect for (includes but is not limited to the following types):\n"
        "1. Intent mismatch:\n"
        "   - Visible UI does not match the triggered action\n"
        "   - Unexpected navigation or external app launch\n"
        "2. Deceptive components:\n"
        "   - Hidden clickable elements\n"
        "   - Fake dialogs\n"
        "   - Overlay or accessibility abuse indicators\n"
        "3. Permission behavior:\n"
        "   - Unexpected permission requests\n"
        "   - Permission escalation patterns\n"
        "4. Event causality:\n"
        "   - User action causing unexpected state changes\n"
        "   - Silent triggers without user interaction\n\n"
        "Do not make a final summary until the available UI/event evidence is sufficiently covered."
    )


def build_api_prompt(deps: AndroidEvidenceDeps) -> str:
    return (
        f"{sample_context(deps)}\n"
        "Task: Independently perform one complete ReAct investigation of trace/API behavior over the whole APK. "
        "Discover and review every available event and API-summary window with your tools, expanding details as needed. "
        "Inspect for (includes but is not limited to the following types):\n"
        "1. Sensitive data access:\n"
        "   - Contacts, SMS, location, files, credentials\n"
        "2. Data leakage:\n"
        "   - Sensitive data leaving the device\n"
        "   - Suspicious network destinations\n"
        "3. Dynamic behavior:\n"
        "   - Dynamic code loading\n"
        "   - Reflection or unusual execution paths\n"
        "4. Abuse patterns:\n"
        "   - SMS sending/interception\n"
        "   - Shell commands\n"
        "   - File manipulation\n\n"
        "Do not make a final summary until the available API/trace evidence is sufficiently covered."
    )


def build_judge_prompt(
    deps: AndroidEvidenceDeps,
    vision_result: VisionAgentResult,
    ui_event_result: UIEventAgentResult,
    api_result: APIAgentResult,
) -> str:
    return (
        f"{sample_context(deps, include_screen_summary=False, include_event_summary=False, include_trace_summary=False)}\n"
        "The following are the final outputs of three independent whole-APK ReAct investigations.\n\n"
        "Vision Agent final summary:\n"
        f"{model_json(vision_result)}\n\n"
        "UI/Event Agent final summary:\n"
        f"{model_json(ui_event_result)}\n\n"
        "API Agent final summary:\n"
        f"{model_json(api_result)}\n\n"
        "Task: Make the single final ruling for this APK. Determine whether it is malicious or benign. "
        "If malicious, provide the malicious family; if benign, set threat_category(Malicious family) to Benign. "
        "Return AndroidMalwareAnalysisOutput directly with a concrete cross-agent evidence chain."
    )


def _normalized_token_usage(value: Any) -> dict[str, int | None]:
    value = value if isinstance(value, dict) else {}
    input_tokens = _usage_field(value, "input_tokens", "request_tokens")
    output_tokens = _usage_field(value, "output_tokens", "response_tokens")
    total_tokens = _usage_field(value, "total_tokens")
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _stage_token_usage(stage_audit: dict[str, Any]) -> dict[str, int | None]:
    direct_usage = _normalized_token_usage(stage_audit.get("token_usage"))
    if direct_usage["total_tokens"] is not None:
        return direct_usage

    input_tokens = 0
    output_tokens = 0
    found_usage = False
    for message in stage_audit.get("new_messages") or []:
        usage = message.get("usage") if isinstance(message, dict) else None
        if not isinstance(usage, dict):
            continue
        found_usage = True
        input_tokens += _usage_field(usage, "input_tokens", "request_tokens") or 0
        output_tokens += _usage_field(usage, "output_tokens", "response_tokens") or 0
    if not found_usage:
        return direct_usage
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
    }


