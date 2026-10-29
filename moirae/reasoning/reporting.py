"""Reporting components extracted from the original Moirae runner."""
import json
import re
import uuid
from pathlib import Path
from typing import Any
from ..config import LEGACY_ROUND_EXECUTION_STRATEGY, OUTPUT_SCHEMA_VERSION, PARALLEL_EVIDENCE_AGENTS, PIPELINE_EXECUTION_STRATEGY, execution_descriptor, utc_now_iso
from .data import atomic_write_chunks, atomic_write_text, json_dump, json_load
from ..config import AGENT_KEYS, TOKEN_SUMMARY_END, TOKEN_SUMMARY_START
from .runtime import _part_field, _stage_token_usage, count_tool_calls, markdown_code_block, public_final_report, render_agent_trace_markdown


def _iter_agent_audits(audit_report: dict[str, Any]):
    analysis = audit_report.get("analysis")
    if isinstance(analysis, dict):
        for stage_audit in analysis.get("stage_audits") or []:
            yield None, "parallel_independent_react", stage_audit
        judge_audit = analysis.get("judge_audit")
        if isinstance(judge_audit, dict):
            yield None, "single_final_judgment", judge_audit
        return

    # Backward-compatible reading of legacy round-based audits.
    for round_record in audit_report.get("round_records") or []:
        round_index = round_record.get("round_index")
        for stage_audit in round_record.get("stage_audits") or []:
            yield round_index, "legacy_round", stage_audit

    forced_final_audit = audit_report.get("forced_final_audit")
    if isinstance(forced_final_audit, dict):
        yield None, "forced_final", forced_final_audit


def build_agent_metrics(audit_report: dict[str, Any]) -> dict[str, Any]:
    calls: list[dict[str, Any]] = []
    summary: dict[str, dict[str, Any]] = {
        key: {
            "calls": 0,
            "logical_runs": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "agent_run_attempt_count": 0,
            "retry_count": 0,
            "retry_wait_seconds": 0.0,
            "attempt_metrics_complete": True,
            "model_request_count": 0,
            "model_request_count_complete": True,
            "tool_call_count": 0,
            "tool_call_count_complete": True,
            "total_seconds": 0.0,
            "average_seconds": 0.0,
            "token_usage": {
                "input_tokens": None,
                "output_tokens": None,
                "total_tokens": None,
                "complete": True,
            },
        }
        for key in AGENT_KEYS.values()
    }

    token_totals = {
        key: {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "known_calls": 0}
        for key in AGENT_KEYS.values()
    }

    for round_index, phase, stage_audit in _iter_agent_audits(audit_report):
        stage_name = str(stage_audit.get("stage") or "")
        agent_key = AGENT_KEYS.get(stage_name)
        if agent_key is None:
            continue
        duration = float(stage_audit.get("duration_seconds") or 0.0)
        status = str(
            stage_audit.get("status")
            or ("failed" if stage_audit.get("error") else "success")
        )
        if status != "success":
            status = "failed"
        token_usage = _stage_token_usage(stage_audit)
        retry_audit = stage_audit.get("retry_audit")
        retry_audit = retry_audit if isinstance(retry_audit, dict) else {}
        attempt_count = _int_or_none(retry_audit.get("attempt_count"))
        retry_count = _int_or_none(retry_audit.get("retry_count"))
        retry_wait_seconds = retry_audit.get("retry_wait_seconds")
        try:
            retry_wait_seconds = (
                float(retry_wait_seconds) if retry_wait_seconds is not None else None
            )
        except (TypeError, ValueError):
            retry_wait_seconds = None
        model_request_count = _int_or_none(stage_audit.get("model_request_count"))
        tool_call_count = _int_or_none(stage_audit.get("tool_call_count"))
        if tool_call_count is None:
            tool_call_count = count_tool_calls(stage_audit.get("new_messages"))
        tool_call_count_complete = stage_audit.get("tool_call_count_complete")
        if not isinstance(tool_call_count_complete, bool):
            tool_call_count_complete = False
        call = {
            "agent": agent_key,
            "phase": phase,
            "logical_run_count": 1,
            "agent_run_attempt_count": attempt_count,
            "retry_count": retry_count,
            "retry_wait_seconds": (
                round(retry_wait_seconds, 3) if retry_wait_seconds is not None else None
            ),
            "model_request_count": model_request_count,
            "model_request_count_complete": (
                model_request_count is not None and retry_count == 0
            ),
            "tool_call_count": tool_call_count,
            "tool_call_count_complete": tool_call_count_complete,
            "execution_group": stage_audit.get("execution_group") or (
                "serial_forced_judge" if phase == "forced_final" else "legacy_unspecified"
            ),
            "parallel_group_id": stage_audit.get("parallel_group_id"),
            "depends_on_parallel_group_id": stage_audit.get("depends_on_parallel_group_id"),
            "started_at_utc": stage_audit.get("started_at_utc"),
            "finished_at_utc": stage_audit.get("finished_at_utc"),
            "duration_seconds": round(duration, 3),
            "status": status,
            "token_usage": token_usage,
        }
        if round_index is not None:
            call["legacy_round_index"] = round_index
        calls.append(call)

        agent_summary = summary[agent_key]
        agent_summary["calls"] += 1
        agent_summary["logical_runs"] += 1
        if status == "success":
            agent_summary["successful_calls"] += 1
        else:
            agent_summary["failed_calls"] += 1
        if attempt_count is None or retry_count is None or retry_wait_seconds is None:
            agent_summary["attempt_metrics_complete"] = False
        else:
            agent_summary["agent_run_attempt_count"] += attempt_count
            agent_summary["retry_count"] += retry_count
            agent_summary["retry_wait_seconds"] += retry_wait_seconds
        if model_request_count is None or retry_count is None or retry_count > 0:
            agent_summary["model_request_count_complete"] = False
        else:
            agent_summary["model_request_count"] += model_request_count
        agent_summary["tool_call_count"] += tool_call_count
        if not tool_call_count_complete:
            agent_summary["tool_call_count_complete"] = False
        agent_summary["total_seconds"] += duration

        if any(token_usage[field] is None for field in ("input_tokens", "output_tokens", "total_tokens")):
            agent_summary["token_usage"]["complete"] = False
        if token_usage["total_tokens"] is not None:
            token_totals[agent_key]["known_calls"] += 1
            for field in ("input_tokens", "output_tokens", "total_tokens"):
                token_totals[agent_key][field] += token_usage[field] or 0

    for agent_key, agent_summary in summary.items():
        call_count = agent_summary["calls"]
        agent_summary["total_seconds"] = round(agent_summary["total_seconds"], 3)
        agent_summary["average_seconds"] = round(
            agent_summary["total_seconds"] / call_count,
            3,
        ) if call_count else 0.0
        agent_summary["retry_wait_seconds"] = round(
            agent_summary["retry_wait_seconds"],
            3,
        )
        if call_count and not agent_summary["attempt_metrics_complete"]:
            agent_summary["agent_run_attempt_count"] = None
            agent_summary["retry_count"] = None
            agent_summary["retry_wait_seconds"] = None
        if call_count and not agent_summary["model_request_count_complete"]:
            agent_summary["model_request_count"] = None
        if call_count and not agent_summary["tool_call_count_complete"]:
            agent_summary["tool_call_count"] = None
        known_calls = token_totals[agent_key]["known_calls"]
        if known_calls:
            for field in ("input_tokens", "output_tokens", "total_tokens"):
                agent_summary["token_usage"][field] = token_totals[agent_key][field]
        elif call_count:
            agent_summary["token_usage"]["complete"] = False

    return {"summary": summary, "calls": calls}


def _compact_judge_decision(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    decision = dict(value)
    decision.pop("final_report", None)
    return decision


def _compact_stage_output(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    output = dict(value)
    output.pop("sample_hash", None)
    return output


def _tool_return_parts(stage_audit: dict[str, Any]):
    for message in stage_audit.get("new_messages") or []:
        for part in _part_field(message, "parts", []) or []:
            if _part_field(part, "part_kind") != "tool-return":
                continue
            tool_name = str(_part_field(part, "tool_name", "")).lower()
            payload = _part_field(part, "return_value")
            if payload is None:
                payload = _part_field(part, "content")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    pass
            yield tool_name, payload, _part_field(part, "metadata")


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _event_ids_in_payload(value: Any) -> set[int]:
    event_ids: set[int] = set()
    if isinstance(value, dict):
        event_id = _int_or_none(value.get("event_id"))
        if event_id is not None:
            event_ids.add(event_id)
        for item in value.get("event_ids") or []:
            event_id = _int_or_none(item)
            if event_id is not None:
                event_ids.add(event_id)
        for key in ("events", "raw_events"):
            event_ids.update(_event_ids_in_payload(value.get(key)))
    elif isinstance(value, list):
        for item in value:
            event_ids.update(_event_ids_in_payload(item))
    return event_ids


def _normalized_api_signature(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("api_signature")
    if not isinstance(value, str) or not value.strip():
        return None
    return re.sub(
        r"\s*\(Call\s+\d+\s+times?\)\s*$",
        "",
        value.strip(),
        flags=re.IGNORECASE,
    )


def build_evidence_usage(
    stage_audits: list[dict[str, Any]],
    states: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Count unique evidence actually returned to each independent Agent."""
    image_refs: set[str] = set()
    ui_state_refs: set[str] = set()
    ui_state_screens: set[int] = set()
    ui_event_ids: set[int] = set()
    api_signatures: set[str] = set()

    states = states or []
    for stage_audit in stage_audits:
        stage_name = str(stage_audit.get("stage") or "")
        for tool_name, payload, metadata in _tool_return_parts(stage_audit):
            payload_dict = payload if isinstance(payload, dict) else {}
            metadata_dict = metadata if isinstance(metadata, dict) else {}

            if stage_name == "Vision Agent" and tool_name == "inspect_screen":
                image_ref = payload_dict.get("image_ref") or metadata_dict.get("image_ref")
                if image_ref and not payload_dict.get("error"):
                    image_refs.add(str(image_ref))

            if stage_name == "UI/Event Agent" and tool_name == "read_ui_state":
                screen_index = _int_or_none(payload_dict.get("screen_index"))
                if screen_index is not None and not payload_dict.get("error"):
                    ui_state_screens.add(screen_index)
                    state_ref = payload_dict.get("state_ref")
                    if 0 <= screen_index < len(states):
                        state = states[screen_index]
                        state_ref = state_ref or state.get("raw_state_file") or state.get("state_file")
                    if state_ref:
                        ui_state_refs.add(str(state_ref))

            if stage_name == "UI/Event Agent" and tool_name in {
                "list_ui_events",
                "read_related_events",
                "read_raw_ui_event",
                "first_related_event",
            }:
                ui_event_ids.update(_event_ids_in_payload(payload))

            if stage_name == "API Agent" and tool_name == "read_api_calls":
                for event_trace in payload_dict.get("api_calls") or []:
                    if not isinstance(event_trace, dict):
                        continue
                    for api_item in event_trace.get("native_behavior_summary") or []:
                        signature = _normalized_api_signature(api_item)
                        if signature:
                            api_signatures.add(signature)

    return {
        "vision_agent": {
            "image_count": len(image_refs),
            "counting_rule": "unique screenshots returned by inspect_screen",
        },
        "ui_event_agent": {
            "ui_state_count": len(ui_state_screens),
            "ui_state_file_count": len(ui_state_refs),
            "event_count": len(ui_event_ids),
            "counting_rule": "unique UI states/state files returned by read_ui_state and unique event_id values returned by event tools",
        },
        "api_agent": {
            "api_count": len(api_signatures),
            "counting_rule": "unique normalized api_signature values returned by read_api_calls",
        },
    }


def evidence_agent_final_results_record(audit_report: dict[str, Any]) -> dict[str, Any]:
    """Build the minimal per-APK context containing only final evidence-agent outputs."""
    analysis = audit_report.get("analysis")
    if isinstance(analysis, dict):
        stage_outputs = analysis.get("stage_outputs") or {}
    else:
        stage_outputs = {}
        for round_record in audit_report.get("round_records") or []:
            if isinstance(round_record.get("stage_outputs"), dict):
                stage_outputs.update(round_record["stage_outputs"])
    return {
        "apk_name": audit_report.get("sample_hash"),
        "vision_agent": stage_outputs.get("vision"),
        "ui_event_agent": stage_outputs.get("ui_event"),
        "api_agent": stage_outputs.get("api"),
    }


def detailed_context_record(audit_report: dict[str, Any]) -> dict[str, Any]:
    """Preserve the former rich context and add real tool-evidence coverage counts."""
    record = compact_context_record(audit_report)
    analysis = audit_report.get("analysis")
    stored_usage = analysis.get("evidence_usage") if isinstance(analysis, dict) else None
    if not isinstance(stored_usage, dict):
        evidence_stages = [
            stage
            for _, _, stage in _iter_agent_audits(audit_report)
            if stage.get("stage") in {"Vision Agent", "UI/Event Agent", "API Agent"}
        ]
        stored_usage = build_evidence_usage(evidence_stages)
    record["evidence_usage"] = stored_usage
    return record


def _legacy_round_execution(round_record: dict[str, Any]) -> dict[str, Any]:
    """Infer concurrency timing for legacy round-based audits."""
    stage_audits = round_record.get("stage_audits") or []
    evidence_audits = [
        stage
        for stage in stage_audits
        if stage.get("stage") in {"Vision Agent", "UI/Event Agent", "API Agent"}
    ]
    judge_audits = [stage for stage in stage_audits if stage.get("stage") == "Judge Agent"]
    evidence_cumulative = sum(float(stage.get("duration_seconds") or 0.0) for stage in evidence_audits)
    parallel_wall = round_record.get("parallel_analysis_duration_seconds")
    if parallel_wall is None:
        parallel_wall = max(
            (float(stage.get("duration_seconds") or 0.0) for stage in evidence_audits),
            default=0.0,
        )
    judge_wall = sum(float(stage.get("duration_seconds") or 0.0) for stage in judge_audits)
    return {
        "strategy": LEGACY_ROUND_EXECUTION_STRATEGY,
        "timing_source": "inferred_from_legacy_audit",
        "started_at_utc": None,
        "finished_at_utc": None,
        "wall_time_seconds": round(float(parallel_wall or 0.0) + judge_wall, 3),
        "phases": {
            "parallel_evidence": {
                "mode": "parallel",
                "agents": list(PARALLEL_EVIDENCE_AGENTS),
                "started_at_utc": None,
                "finished_at_utc": None,
                "wall_time_seconds": round(float(parallel_wall or 0.0), 3),
                "cumulative_agent_time_seconds": round(evidence_cumulative, 3),
                "parallel_savings_seconds": round(
                    max(evidence_cumulative - float(parallel_wall or 0.0), 0.0),
                    3,
                ),
            },
            "serial_judge": {
                "mode": "serial_after_barrier",
                "agent": "judge_agent",
                "depends_on": "parallel_evidence",
                "started_at_utc": None,
                "finished_at_utc": None,
                "wall_time_seconds": round(judge_wall, 3),
            },
        },
    }


def compact_context_record(audit_report: dict[str, Any]) -> dict[str, Any]:
    analysis = audit_report.get("analysis")
    if isinstance(analysis, dict):
        stage_outputs = analysis.get("stage_outputs") or {}
        stage_audits = list(analysis.get("stage_audits") or [])
        if isinstance(analysis.get("judge_audit"), dict):
            stage_audits.append(analysis["judge_audit"])
        compact_record = {
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "document_type": "multi_agent_compact_context",
            "run_id": audit_report.get("run_id"),
            "source_index": audit_report.get("source_index"),
            "sample_hash": audit_report.get("sample_hash"),
            "finished": audit_report.get("finished"),
            "execution": audit_report.get("execution") or execution_descriptor(),
            "source_counts": audit_report.get("source_counts"),
            "analysis": {
                "execution": analysis.get("execution"),
                "stage_outputs": {
                    key: _compact_stage_output(value)
                    for key, value in stage_outputs.items()
                },
                "agent_metrics": [
                    {
                        "agent": AGENT_KEYS.get(str(stage.get("stage") or ""), stage.get("stage")),
                        "execution_group": stage.get("execution_group"),
                        "parallel_group_id": stage.get("parallel_group_id"),
                        "depends_on_parallel_group_id": stage.get("depends_on_parallel_group_id"),
                        "started_at_utc": stage.get("started_at_utc"),
                        "finished_at_utc": stage.get("finished_at_utc"),
                        "duration_seconds": stage.get("duration_seconds"),
                        "token_usage": _stage_token_usage(stage),
                        "status": "failed" if stage.get("error") else "success",
                    }
                    for stage in stage_audits
                ],
                "judge_output": analysis.get("judge_output"),
            },
        }
        if audit_report.get("error"):
            compact_record["error"] = audit_report["error"]
        return compact_record

    # Backward-compatible compaction for legacy round-based audit files.
    compact_rounds = []
    for round_record in audit_report.get("round_records") or []:
        stage_outputs = round_record.get("stage_outputs") or {}
        compact_rounds.append(
            {
                "round_index": round_record.get("round_index"),
                "timeline_item": round_record.get("timeline_item"),
                "all_information_exhausted": round_record.get("all_information_exhausted"),
                "execution": round_record.get("execution") or _legacy_round_execution(round_record),
                "parallel_analysis_duration_seconds": round_record.get("parallel_analysis_duration_seconds"),
                "stage_outputs": {
                    key: _compact_stage_output(value)
                    for key, value in stage_outputs.items()
                },
                "agent_metrics": [
                    {
                        "agent": AGENT_KEYS.get(str(stage.get("stage") or ""), stage.get("stage")),
                        "execution_group": stage.get("execution_group") or "legacy_unspecified",
                        "parallel_group_id": stage.get("parallel_group_id"),
                        "depends_on_parallel_group_id": stage.get("depends_on_parallel_group_id"),
                        "started_at_utc": stage.get("started_at_utc"),
                        "finished_at_utc": stage.get("finished_at_utc"),
                        "duration_seconds": stage.get("duration_seconds"),
                        "token_usage": _stage_token_usage(stage),
                        "status": "failed" if stage.get("error") else "success",
                    }
                    for stage in round_record.get("stage_audits") or []
                ],
                "judge_decision": _compact_judge_decision(round_record.get("judge_decision")),
            }
        )

    compact_record = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "document_type": "multi_agent_compact_context",
        "run_id": audit_report.get("run_id"),
        "source_index": audit_report.get("source_index"),
        "sample_hash": audit_report.get("sample_hash"),
        "finished": audit_report.get("finished"),
        "execution": audit_report.get("execution") or execution_descriptor(),
        "source_counts": audit_report.get("source_counts"),
        "timeline_total": audit_report.get("timeline_total"),
        "rounds_completed": audit_report.get("rounds_completed"),
        "final_decision": _compact_judge_decision(audit_report.get("final_judge_decision")),
        "round_records": compact_rounds,
    }
    if audit_report.get("error"):
        compact_record["error"] = audit_report["error"]
    if isinstance(audit_report.get("forced_final_audit"), dict):
        forced = audit_report["forced_final_audit"]
        compact_record["forced_final_metric"] = {
            "agent": "judge_agent",
            "duration_seconds": forced.get("duration_seconds"),
            "token_usage": _stage_token_usage(forced),
            "status": "failed" if forced.get("error") else "success",
        }
    return compact_record


def critical_path_agent_time(audit_report: dict[str, Any]) -> float:
    """Measure wall-clock agent time without double-counting parallel evidence calls."""
    analysis = audit_report.get("analysis")
    if isinstance(analysis, dict):
        phases = ((analysis.get("execution") or {}).get("phases") or {})
        parallel = phases.get("parallel_independent_react") or {}
        judge = phases.get("single_judge") or {}
        parallel_time = parallel.get("wall_time_seconds")
        if parallel_time is None:
            parallel_time = max(
                (
                    float(stage.get("duration_seconds") or 0.0)
                    for stage in analysis.get("stage_audits") or []
                ),
                default=0.0,
            )
        judge_time = judge.get("wall_time_seconds")
        if judge_time is None and isinstance(analysis.get("judge_audit"), dict):
            judge_time = analysis["judge_audit"].get("duration_seconds")
        return float(parallel_time or 0.0) + float(judge_time or 0.0)

    # Backward-compatible timing for legacy round-based audit files.
    total = 0.0
    for round_record in audit_report.get("round_records") or []:
        stage_audits = round_record.get("stage_audits") or []
        parallel_duration = round_record.get("parallel_analysis_duration_seconds")
        if parallel_duration is None:
            evidence_durations = [
                float(stage.get("duration_seconds") or 0.0)
                for stage in stage_audits
                if stage.get("stage") in {"Vision Agent", "UI/Event Agent", "API Agent"}
            ]
            parallel_duration = max(evidence_durations, default=0.0)
        total += float(parallel_duration or 0.0)
        total += sum(
            float(stage.get("duration_seconds") or 0.0)
            for stage in stage_audits
            if stage.get("stage") == "Judge Agent"
        )

    forced_final = audit_report.get("forced_final_audit")
    if isinstance(forced_final, dict):
        total += float(forced_final.get("duration_seconds") or 0.0)
    return total


def build_timing_record(
    apk_name: str,
    audit_report: dict[str, Any],
    total_duration: float,
    status: str,
) -> dict[str, Any]:
    agent_metrics = build_agent_metrics(audit_report)
    agent_calls = agent_metrics["calls"]
    cumulative_agent_time = sum(
        float(call.get("duration_seconds") or 0.0)
        for call in agent_calls
    )
    measured_agent_time = critical_path_agent_time(audit_report)
    attempt_metrics_complete = bool(agent_calls) and all(
        call.get("agent_run_attempt_count") is not None
        and call.get("retry_count") is not None
        and call.get("retry_wait_seconds") is not None
        for call in agent_calls
    )
    model_request_metrics_complete = bool(agent_calls) and all(
        bool(call.get("model_request_count_complete")) for call in agent_calls
    )
    tool_call_metrics_complete = bool(agent_calls) and all(
        bool(call.get("tool_call_count_complete")) for call in agent_calls
    )
    call_summary = {
        "logical_agent_run_count": len(agent_calls),
        "successful_logical_run_count": sum(
            1 for call in agent_calls if call.get("status") == "success"
        ),
        "failed_logical_run_count": sum(
            1 for call in agent_calls if call.get("status") != "success"
        ),
        "agent_run_attempt_count": (
            sum(int(call["agent_run_attempt_count"]) for call in agent_calls)
            if attempt_metrics_complete
            else None
        ),
        "retry_count": (
            sum(int(call["retry_count"]) for call in agent_calls)
            if attempt_metrics_complete
            else None
        ),
        "retry_wait_seconds": (
            round(sum(float(call["retry_wait_seconds"]) for call in agent_calls), 3)
            if attempt_metrics_complete
            else None
        ),
        "attempt_metrics_complete": attempt_metrics_complete,
        "model_request_count": (
            sum(int(call["model_request_count"]) for call in agent_calls)
            if model_request_metrics_complete
            else None
        ),
        "model_request_metrics_complete": model_request_metrics_complete,
        "tool_call_count": (
            sum(int(call.get("tool_call_count") or 0) for call in agent_calls)
            if tool_call_metrics_complete
            else None
        ),
        "tool_call_metrics_complete": tool_call_metrics_complete,
        "counting_notes": {
            "logical_agent_run_count": "One recorded Vision, UI/Event, API, or Judge stage.",
            "agent_run_attempt_count": "Top-level agent.run attempts, including the initial attempt.",
            "retry_count": "Top-level attempts after the initial attempt.",
            "model_request_count": "Provider requests exposed by the successful PydanticAI result; null when incomplete.",
            "tool_call_count": "Tool-call message parts in successful Agent results.",
        },
    }
    return {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "document_type": "multi_agent_sample_timing",
        "run_id": audit_report.get("run_id"),
        "source_index": audit_report.get("source_index"),
        "apk_name": apk_name,
        "input_report": f"sample:{apk_name}/fused_api_report.json",
        "status": status,
        "execution": {
            "pipeline_strategy": PIPELINE_EXECUTION_STRATEGY,
            "parallel_evidence_agents": list(PARALLEL_EVIDENCE_AGENTS),
        },
        "timing": {
            "sample_wall_time_seconds": round(total_duration, 3),
            "critical_path_agent_time_seconds": round(measured_agent_time, 3),
            "cumulative_agent_call_time_seconds": round(cumulative_agent_time, 3),
            "parallel_savings_seconds": round(
                max(cumulative_agent_time - measured_agent_time, 0.0),
                3,
            ),
            "pipeline_overhead_seconds": round(max(total_duration - measured_agent_time, 0.0), 3),
        },
        "call_summary": call_summary,
        "agent_summary": agent_metrics["summary"],
        "agent_calls": agent_calls,
    }


def aggregate_call_statistics(timing_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-sample call telemetry while exposing completeness."""
    summaries = [
        record.get("call_summary")
        for record in timing_records
        if isinstance(record.get("call_summary"), dict)
    ]

    def mean(values: list[float]) -> float | None:
        return round(sum(values) / len(values), 3) if values else None

    attempt_complete = [
        item for item in summaries if item.get("attempt_metrics_complete") is True
    ]
    model_complete = [
        item for item in summaries if item.get("model_request_metrics_complete") is True
    ]
    tool_complete = [
        item for item in summaries if item.get("tool_call_metrics_complete") is True
    ]
    return {
        "sample_count": len(summaries),
        "mean_logical_agent_runs_per_sample": mean(
            [float(item.get("logical_agent_run_count") or 0) for item in summaries]
        ),
        "mean_agent_run_attempts_per_complete_sample": mean(
            [float(item["agent_run_attempt_count"]) for item in attempt_complete]
        ),
        "mean_retries_per_complete_sample": mean(
            [float(item["retry_count"]) for item in attempt_complete]
        ),
        "mean_retry_wait_seconds_per_complete_sample": mean(
            [float(item["retry_wait_seconds"]) for item in attempt_complete]
        ),
        "attempt_metrics_complete_samples": len(attempt_complete),
        "mean_model_requests_per_complete_sample": mean(
            [float(item["model_request_count"]) for item in model_complete]
        ),
        "model_request_metrics_complete_samples": len(model_complete),
        "mean_tool_calls_per_complete_sample": mean(
            [float(item["tool_call_count"]) for item in tool_complete]
        ),
        "tool_call_metrics_complete_samples": len(tool_complete),
    }


def _markdown_table_cell(value: Any) -> str:
    return str(value if value is not None else "N/A").replace("|", "\\|").replace("\n", " ")


def render_sample_trace_markdown(
    audit_report: dict[str, Any],
    final_report: dict[str, Any] | None = None,
) -> str:
    """Render an entire sample deterministically after concurrent calls have joined."""
    sample_hash = str(audit_report.get("sample_hash") or "unknown")
    execution = audit_report.get("execution") or execution_descriptor()
    lines = [
        f"## Sample {int(audit_report.get('source_index')) + 1:05d} "
        f"(source_index={int(audit_report.get('source_index'))}) - `{sample_hash}`"
        if audit_report.get("source_index") is not None
        else f"## Sample `{sample_hash}`",
        "",
        f"- Status: `{'finished' if audit_report.get('finished') else 'failed'}`",
        f"- Started (UTC): `{execution.get('started_at_utc') or 'N/A'}`",
        f"- Finished (UTC): `{execution.get('finished_at_utc') or 'N/A'}`",
        f"- Sample wall time: `{float(execution.get('sample_wall_time_seconds') or 0.0):.3f}s`",
        f"- Pipeline strategy: `{execution.get('pipeline_strategy') or PIPELINE_EXECUTION_STRATEGY}`",
        "",
    ]

    evidence_order = ["Vision Agent", "UI/Event Agent", "API Agent"]
    analysis = audit_report.get("analysis")
    if isinstance(analysis, dict):
        analysis_execution = analysis.get("execution") or {}
        parallel_phase = (analysis_execution.get("phases") or {}).get("parallel_independent_react") or {}
        stage_audits = analysis.get("stage_audits") or []
        stage_by_name = {
            str(stage.get("stage") or ""): stage
            for stage in stage_audits
            if isinstance(stage, dict)
        }
        lines.extend(
            [
                "### Phase 1 - independent whole-APK ReAct agents",
                "",
                "> Vision, UI/Event, and API agents each investigate the complete APK independently and run concurrently.",
                "",
                "| Agent | Started (UTC) | Finished (UTC) | Duration (s) | Status |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
        for stage_name in evidence_order:
            stage = stage_by_name.get(stage_name) or {"stage": stage_name, "status": "missing"}
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_table_cell(AGENT_KEYS.get(stage_name, stage_name)),
                        _markdown_table_cell(stage.get("started_at_utc")),
                        _markdown_table_cell(stage.get("finished_at_utc")),
                        _markdown_table_cell(stage.get("duration_seconds")),
                        _markdown_table_cell("failed" if stage.get("error") else stage.get("status") or "success"),
                    ]
                )
                + " |"
            )
        lines.extend(
            [
                "",
                "Parallel timing: "
                f"wall `{float(parallel_phase.get('wall_time_seconds') or 0.0):.3f}s`, "
                f"cumulative Agent time `{float(parallel_phase.get('cumulative_agent_time_seconds') or 0.0):.3f}s`, "
                f"saved `{float(parallel_phase.get('parallel_savings_seconds') or 0.0):.3f}s`.",
                "",
            ]
        )
        for stage_name in evidence_order:
            stage = stage_by_name.get(stage_name)
            if stage is not None:
                lines.extend([render_agent_trace_markdown(stage, heading_level=4), ""])

        lines.extend(
            [
                "### Synchronization barrier",
                "",
                "> All three whole-APK ReAct analyses are complete. The Judge is invoked once with their final outputs.",
                "",
                "### Phase 2 - single final Judge",
                "",
            ]
        )
        judge_audit = analysis.get("judge_audit")
        if isinstance(judge_audit, dict):
            lines.extend([render_agent_trace_markdown(judge_audit, heading_level=4), ""])
        if final_report is None:
            final_report = analysis.get("judge_output") or audit_report.get("judge_output")
        lines.extend(
            [
                "### Final report",
                "",
                markdown_code_block(json.dumps(final_report, indent=2, ensure_ascii=False), "json"),
                "",
                "---",
                "",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    # Backward-compatible rendering for legacy round-based audit files.
    for round_record in audit_report.get("round_records") or []:
        round_index = round_record.get("round_index")
        round_execution = round_record.get("execution") or _legacy_round_execution(round_record)
        parallel_phase = (round_execution.get("phases") or {}).get("parallel_evidence") or {}
        stage_audits = round_record.get("stage_audits") or []
        stage_by_name = {
            str(stage.get("stage") or ""): stage
            for stage in stage_audits
            if isinstance(stage, dict)
        }
        lines.extend(
            [
                f"### Round {round_index}",
                "",
                f"- Timeline index: `{(round_record.get('timeline_item') or {}).get('timeline_index')}`",
                f"- Round wall time: `{float(round_execution.get('wall_time_seconds') or 0.0):.3f}s`",
                "",
                "#### Phase 1 — parallel evidence agents",
                "",
                "> Vision, UI/Event, and API analysis start independently. The Judge waits at the barrier below.",
                "",
                "| Agent | Started (UTC) | Finished (UTC) | Duration (s) | Status |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
        for stage_name in evidence_order:
            stage = stage_by_name.get(stage_name) or {"stage": stage_name, "status": "missing"}
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_table_cell(AGENT_KEYS.get(stage_name, stage_name)),
                        _markdown_table_cell(stage.get("started_at_utc")),
                        _markdown_table_cell(stage.get("finished_at_utc")),
                        _markdown_table_cell(stage.get("duration_seconds")),
                        _markdown_table_cell("failed" if stage.get("error") else stage.get("status") or "success"),
                    ]
                )
                + " |"
            )
        lines.extend(
            [
                "",
                "Parallel timing: "
                f"wall `{float(parallel_phase.get('wall_time_seconds') or 0.0):.3f}s`, "
                f"cumulative Agent time `{float(parallel_phase.get('cumulative_agent_time_seconds') or 0.0):.3f}s`, "
                f"saved `{float(parallel_phase.get('parallel_savings_seconds') or 0.0):.3f}s`.",
                "",
            ]
        )
        for stage_name in evidence_order:
            stage = stage_by_name.get(stage_name)
            if stage is not None:
                lines.extend([render_agent_trace_markdown(stage, heading_level=5), ""])

        lines.extend(
            [
                "#### Synchronization barrier",
                "",
                "> All parallel evidence agents have completed; the Judge may now consume all three results.",
                "",
                "#### Phase 2 — serial Judge",
                "",
            ]
        )
        judge_audit = stage_by_name.get("Judge Agent")
        if judge_audit is not None:
            lines.extend([render_agent_trace_markdown(judge_audit, heading_level=5), ""])

    forced_final = audit_report.get("forced_final_audit")
    if isinstance(forced_final, dict):
        lines.extend(
            [
                "### Forced final judgment",
                "",
                render_agent_trace_markdown(forced_final, heading_level=4),
                "",
            ]
        )

    if final_report is None:
        decision = audit_report.get("final_judge_decision") or {}
        final_report = decision.get("final_report") if isinstance(decision, dict) else None
    lines.extend(
        [
            "### Final report",
            "",
            markdown_code_block(json.dumps(final_report, indent=2, ensure_ascii=False), "json"),
            "",
            "---",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def build_trace_header(session_started_at_utc: str) -> str:
    return "\n".join(
        [
            "# Multi-Agent Dynamic Evidence Reasoning Trace",
            "",
            f"- Schema version: `{OUTPUT_SCHEMA_VERSION}`",
            f"- Session started (UTC): `{session_started_at_utc}`",
            f"- Last updated (UTC): `{utc_now_iso()}`",
            "- Sample scheduling: `sequential`",
            f"- Pipeline strategy: `{PIPELINE_EXECUTION_STRATEGY}`",
            "- Parallel phase: one whole-APK ReAct invocation each for `vision_agent`, `ui_event_agent`, and `api_agent`",
            "- Barrier: the single Judge invocation starts only after all three evidence agents finish",
            "",
        ]
    )


def build_trace_document(
    session_started_at_utc: str,
    sample_traces: list[str],
    audit_reports: list[dict[str, Any]],
) -> str:
    header = build_trace_header(session_started_at_utc)
    body = "\n".join(trace.rstrip() for trace in sample_traces)
    summary = build_token_summary_markdown(audit_reports)
    return f"{header}\n{body}\n\n{summary}" if body else f"{header}\n{summary}"


def write_trace_document(
    trace_path: str | Path,
    session_started_at_utc: str,
    sample_trace_paths: list[Path],
    audit_reports: list[dict[str, Any]],
) -> None:
    def chunks():
        yield build_trace_header(session_started_at_utc)
        for sample_trace_path in sample_trace_paths:
            yield "\n"
            yield sample_trace_path.read_text(encoding="utf-8", errors="ignore").rstrip()
            yield "\n"
        yield "\n"
        yield build_token_summary_markdown(audit_reports)

    atomic_write_chunks(trace_path, chunks())


def build_collection_document(
    document_type: str,
    item_key: str,
    items: list[dict[str, Any]],
    summary: dict[str, Any],
    run_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "document_type": document_type,
        "generated_at_utc": utc_now_iso(),
        "run": run_metadata or {"run_id": None, "metadata_source": "legacy_rebuild"},
        "execution": execution_descriptor(),
        "summary": summary,
        item_key: items,
    }


def build_token_summary_markdown(audit_reports: list[dict[str, Any]]) -> str:
    lines = [
        TOKEN_SUMMARY_START,
        "## Concurrency and token summary",
        "",
        "Wall time measures elapsed time. Cumulative Agent time sums concurrent calls and must not be used as elapsed batch time.",
        "",
        "### Whole-APK pipeline timing",
        "",
        "| APK | Scope | Parallel wall (s) | Cumulative evidence time (s) | Saved (s) | Single Judge (s) |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]

    def display(value: Any) -> str:
        return str(value) if value is not None else "N/A"

    for audit_report in audit_reports:
        sample_hash = str(audit_report.get("sample_hash") or "unknown")
        analysis = audit_report.get("analysis")
        if isinstance(analysis, dict):
            phases = ((analysis.get("execution") or {}).get("phases") or {})
            parallel = phases.get("parallel_independent_react") or {}
            judge = phases.get("single_judge") or {}
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_table_cell(sample_hash),
                        "whole_apk",
                        display(parallel.get("wall_time_seconds")),
                        display(parallel.get("cumulative_agent_time_seconds")),
                        display(parallel.get("parallel_savings_seconds")),
                        display(judge.get("wall_time_seconds")),
                    ]
                )
                + " |"
            )
            continue

        # Backward-compatible rows for legacy round-based audits.
        for round_record in audit_report.get("round_records") or []:
            execution = round_record.get("execution") or _legacy_round_execution(round_record)
            phases = execution.get("phases") or {}
            parallel = phases.get("parallel_evidence") or {}
            judge = phases.get("serial_judge") or {}
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_table_cell(sample_hash),
                        f"legacy_round_{display(round_record.get('round_index'))}",
                        display(parallel.get("wall_time_seconds")),
                        display(parallel.get("cumulative_agent_time_seconds")),
                        display(parallel.get("parallel_savings_seconds")),
                        display(judge.get("wall_time_seconds")),
                    ]
                )
                + " |"
            )

    lines.extend(
        [
            "",
            "### Agent calls and tokens",
            "",
            "`N/A` means the provider or a legacy audit did not expose that field.",
            "",
            "| APK | Scope | Execution group | Agent | Logical runs | agent.run attempts | Retries | Retry wait (s) | Model requests | Tool calls | Started (UTC) | Finished (UTC) | Input tokens | Output tokens | Total tokens | Duration (s) | Status |",
            "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )

    for audit_report in audit_reports:
        sample_hash = str(audit_report.get("sample_hash") or "unknown")
        for call in build_agent_metrics(audit_report)["calls"]:
            usage = call.get("token_usage") or {}
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_table_cell(sample_hash),
                        (
                            f"legacy_round_{display(call.get('legacy_round_index'))}"
                            if call.get("legacy_round_index") is not None
                            else _markdown_table_cell(call.get("phase") or "whole_apk")
                        ),
                        _markdown_table_cell(call.get("execution_group") or call.get("phase") or "unknown"),
                        _markdown_table_cell(call.get("agent") or "unknown"),
                        display(call.get("logical_run_count")),
                        display(call.get("agent_run_attempt_count")),
                        display(call.get("retry_count")),
                        display(call.get("retry_wait_seconds")),
                        display(call.get("model_request_count")),
                        display(call.get("tool_call_count")),
                        display(call.get("started_at_utc")),
                        display(call.get("finished_at_utc")),
                        display(usage.get("input_tokens")),
                        display(usage.get("output_tokens")),
                        display(usage.get("total_tokens")),
                        display(call.get("duration_seconds")),
                        str(call.get("status") or "unknown"),
                    ]
                )
                + " |"
            )
    lines.extend([TOKEN_SUMMARY_END, ""])
    return "\n".join(lines)


def _document_items(document: Any, item_key: str) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if isinstance(document, dict) and isinstance(document.get(item_key), list):
        return [item for item in document[item_key] if isinstance(item, dict)]
    return []


def _timing_value(record: dict[str, Any], new_key: str, *legacy_keys: str) -> float | None:
    timing = record.get("timing") if isinstance(record.get("timing"), dict) else {}
    value = timing.get(new_key)
    if value is None:
        for key in legacy_keys:
            value = record.get(key)
            if value is not None:
                break
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def upgrade_audit_report(audit_report: dict[str, Any], sample_wall_time: float | None = None) -> dict[str, Any]:
    audit_report["schema_version"] = OUTPUT_SCHEMA_VERSION
    audit_report["document_type"] = "multi_agent_sample_audit"
    sample_execution = {**execution_descriptor(), **(audit_report.get("execution") or {})}
    if sample_wall_time is not None and sample_execution.get("sample_wall_time_seconds") is None:
        sample_execution["sample_wall_time_seconds"] = round(sample_wall_time, 3)
    audit_report["execution"] = sample_execution

    analysis = audit_report.get("analysis")
    if isinstance(analysis, dict):
        parallel_group_id = f"{audit_report.get('sample_hash')}:parallel_evidence"
        for stage in analysis.get("stage_audits") or []:
            if not isinstance(stage, dict):
                continue
            stage.setdefault("execution_group", "parallel_evidence")
            stage.setdefault("parallel_group_id", parallel_group_id)
            stage.setdefault("status", "failed" if stage.get("error") else "success")
        judge = analysis.get("judge_audit")
        if isinstance(judge, dict):
            judge.setdefault("execution_group", "single_judge")
            judge.setdefault("depends_on_parallel_group_id", parallel_group_id)
            judge.setdefault("status", "failed" if judge.get("error") else "success")
        return audit_report

    # Backward-compatible migration for legacy round-based audits.
    for round_record in audit_report.get("round_records") or []:
        round_record["execution"] = round_record.get("execution") or _legacy_round_execution(round_record)
        round_index = round_record.get("round_index")
        parallel_group_id = f"{audit_report.get('sample_hash')}:round:{round_index}:parallel_evidence"
        for stage in round_record.get("stage_audits") or []:
            if not isinstance(stage, dict):
                continue
            is_judge = stage.get("stage") == "Judge Agent"
            stage.setdefault("execution_group", "serial_judge" if is_judge else "parallel_evidence")
            stage.setdefault("status", "failed" if stage.get("error") else "success")
            stage.setdefault("round_index", round_index)
            if is_judge:
                stage.setdefault("depends_on_parallel_group_id", parallel_group_id)
            else:
                stage.setdefault("parallel_group_id", parallel_group_id)
    forced = audit_report.get("forced_final_audit")
    if isinstance(forced, dict):
        forced.setdefault("execution_group", "serial_forced_judge")
        forced.setdefault("status", "failed" if forced.get("error") else "success")
    return audit_report


def rebuild_existing_outputs(output_dir: str | Path) -> None:
    output_dir = Path(output_dir)
    audit_dir = output_dir / "multi_agent_audits"
    audit_paths = sorted(audit_dir.glob("*.multi_agent_audit.json"))
    if not audit_paths:
        raise SystemExit(f"No multi-agent audit files found: {audit_dir}")

    audit_reports = [json_load(path) for path in audit_paths]
    context_path = output_dir / "all_apks_multi_agent_context.json"
    detailed_context_path = output_dir / "all_apks_multi_agent_detailed_context.json"
    timing_path = output_dir / "timing_stats.json"
    analysis_path = output_dir / "multi_agent_analysis_reports.json"
    trace_path = output_dir / "llm_multi_agent_trace_full.md"

    old_timing = json_load(timing_path) if timing_path.exists() else {}
    old_timing_details = _document_items(old_timing, "details")
    old_details = {
        item.get("apk_name"): item
        for item in old_timing_details
        if isinstance(item, dict) and item.get("apk_name")
    }
    analysis_document = json_load(analysis_path) if analysis_path.exists() else []
    existing_analysis_reports = _document_items(analysis_document, "reports")
    existing_reports_by_sample = {
        str(report.get("apk_name") or ""): report
        for report in existing_analysis_reports
        if report.get("apk_name")
    }
    rebuild_started_at_utc = utc_now_iso()
    rebuild_run_id = uuid.uuid4().hex

    timing_records = []
    for source_index, (audit_path, audit) in enumerate(zip(audit_paths, audit_reports)):
        sample_hash = str(audit.get("sample_hash") or "unknown")
        old_record = old_details.get(sample_hash) or {}
        total_duration = _timing_value(
            old_record,
            "sample_wall_time_seconds",
            "multi_agent_analysis_time",
            "total_time",
        )
        if total_duration is None:
            total_duration = float(
                (audit.get("execution") or {}).get("sample_wall_time_seconds")
                or critical_path_agent_time(audit)
            )
        audit["run_id"] = rebuild_run_id
        audit["source_index"] = source_index
        upgrade_audit_report(audit, total_duration)
        json_dump(audit_path, audit)
        status = str(old_record.get("status") or ("success" if audit.get("finished") else "failed"))
        timing_records.append(build_timing_record(sample_hash, audit, total_duration, status))

    source_index_by_sample = {
        str(audit.get("sample_hash") or ""): audit.get("source_index")
        for audit in audit_reports
    }
    status_by_sample = {
        str(record.get("apk_name") or ""): str(record.get("status") or "failed")
        for record in timing_records
    }
    analysis_reports: list[dict[str, Any]] = []
    for audit in audit_reports:
        sample_hash = str(audit.get("sample_hash") or "unknown")
        analysis = audit.get("analysis")
        raw_report = existing_reports_by_sample.get(sample_hash)
        if raw_report is None and isinstance(analysis, dict):
            raw_report = analysis.get("judge_output")
        if raw_report is None:
            raw_report = audit.get("judge_output")
        if raw_report is None and isinstance(audit.get("final_judge_decision"), dict):
            raw_report = audit["final_judge_decision"].get("final_report")
        source_index = int(source_index_by_sample.get(sample_hash) or 0)
        analysis_reports.append(
            public_final_report(
                raw_report,
                sample_hash,
                source_index,
                status_by_sample.get(sample_hash, "failed"),
            )
        )
    analysis_reports.sort(
        key=lambda report: (
            report.get("source_index") is None,
            report.get("source_index") if report.get("source_index") is not None else float("inf"),
            str(report.get("apk_name") or ""),
        )
    )

    context_records = [evidence_agent_final_results_record(audit) for audit in audit_reports]
    detailed_records = [detailed_context_record(audit) for audit in audit_reports]
    old_summary = old_timing.get("summary") or old_timing.get("batch_summary") or {}
    audited_samples = {str(audit.get("sample_hash") or "") for audit in audit_reports}
    analyzed_audits = [
        item
        for item in analysis_reports
        if str(item.get("apk_name") or "") in audited_samples
    ]
    malicious_count = sum(
        1
        for item in analyzed_audits
        if item.get("status") == "success" and item.get("is_malicious") is True
    )
    benign_count = sum(
        1
        for item in analyzed_audits
        if item.get("status") == "success" and item.get("is_malicious") is False
    )
    failed_count = sum(1 for item in timing_records if item.get("status") != "success")
    classification_summary = {
        "total_reports_input": old_summary.get("total_reports_input", len(audit_reports)),
        "processed_reports": len(audit_reports),
        "malicious": malicious_count,
        "benign": benign_count,
        "failed": failed_count,
    }
    timing_summary = {
        **classification_summary,
        "batch_wall_time_seconds": old_summary.get("batch_wall_time_seconds", old_summary.get("total_duration_seconds")),
        "sum_sample_wall_time_seconds": round(
            sum(float((item.get("timing") or {}).get("sample_wall_time_seconds") or 0.0) for item in timing_records),
            3,
        ),
        "sum_critical_path_agent_time_seconds": round(
            sum(
                float((item.get("timing") or {}).get("critical_path_agent_time_seconds") or 0.0)
                for item in timing_records
            ),
            3,
        ),
        "sum_cumulative_agent_call_time_seconds": round(
            sum(
                float((item.get("timing") or {}).get("cumulative_agent_call_time_seconds") or 0.0)
                for item in timing_records
            ),
            3,
        ),
        "sum_parallel_savings_seconds": round(
            sum(float((item.get("timing") or {}).get("parallel_savings_seconds") or 0.0) for item in timing_records),
            3,
        ),
        "call_statistics": aggregate_call_statistics(timing_records),
    }
    run_metadata = {
        "run_id": rebuild_run_id,
        "started_at_utc": rebuild_started_at_utc,
        "finished_at_utc": utc_now_iso(),
        "metadata_source": "rebuild_existing_outputs",
        "input_source": str(audit_dir),
        "total_reports_input": classification_summary["total_reports_input"],
    }

    json_dump(
        analysis_path,
        analysis_reports,
    )
    json_dump(
        context_path,
        context_records,
    )
    json_dump(
        detailed_context_path,
        build_collection_document(
            "all_apks_multi_agent_detailed_context",
            "records",
            detailed_records,
            classification_summary,
            run_metadata,
        ),
    )
    json_dump(
        timing_path,
        build_collection_document(
            "multi_agent_timing_statistics",
            "details",
            timing_records,
            timing_summary,
            run_metadata,
        ),
    )

    reports_by_sample = {
        str(report.get("apk_name") or ""): report
        for report in analysis_reports
        if report.get("apk_name")
    }
    trace_dir = output_dir / "multi_agent_traces"
    sample_trace_paths: list[Path] = []
    for audit in audit_reports:
        sample_hash = str(audit.get("sample_hash") or "unknown")
        source_index = int(audit.get("source_index") or 0)
        sample_trace_path = trace_dir / f"{source_index:05d}_{sample_hash}.md"
        atomic_write_text(
            sample_trace_path,
            render_sample_trace_markdown(
                audit,
                reports_by_sample.get(sample_hash),
            ),
        )
        sample_trace_paths.append(sample_trace_path)
    known_starts = [
        (audit.get("execution") or {}).get("started_at_utc")
        for audit in audit_reports
        if (audit.get("execution") or {}).get("started_at_utc")
    ]
    session_started_at_utc = min(known_starts) if known_starts else utc_now_iso()
    write_trace_document(
        trace_path,
        session_started_at_utc,
        sample_trace_paths,
        audit_reports,
    )

    print(f"Rebuilt schema-{OUTPUT_SCHEMA_VERSION} analysis reports: {analysis_path}")
    print(f"Rebuilt evidence Agent final results for {len(audit_reports)} APK(s): {context_path}")
    print(f"Rebuilt detailed context and evidence counts: {detailed_context_path}")
    print(f"Rebuilt concurrency-aware timing statistics: {timing_path}")
    print(f"Rebuilt grouped Markdown trace: {trace_path}")


