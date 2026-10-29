"""Pipeline components extracted from the original Moirae runner."""
import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any
from ..evidence.tools import llm_safe_report_ref, safe_exception_text
from .agents import api_agent, judge_agent, ui_event_agent, vision_agent
from ..config import AGENT_REPORT_DIR, BASE_URL, JUDGE_MODEL_NAME, OUTPUT_SCHEMA_VERSION, PARALLEL_EVIDENCE_AGENTS, PIPELINE_EXECUTION_STRATEGY, REASONING_OUTPUT_DIR, RunnerConfig, TEXT_MODEL_NAME, VISION_MODEL_NAME, execution_descriptor, retry_policy_descriptor, utc_now_iso
from .data import atomic_write_text, build_evidence_deps, collect_reports, json_dump, json_load, sample_context
from .reporting import aggregate_call_statistics, build_collection_document, build_evidence_usage, build_timing_record, detailed_context_record, evidence_agent_final_results_record, render_sample_trace_markdown, write_trace_document
from .runtime import build_api_prompt, build_judge_prompt, build_ui_event_prompt, build_vision_prompt, count_tool_calls, extract_model_request_count, extract_token_usage, isolated_agent_deps, model_from_result, normalize_final_report_apk_name, public_final_report, result_method_value, result_text, run_agent_with_retry, run_stage, serialize_value
from .schemas import APIAgentResult, AndroidMalwareAnalysisOutput, UIEventAgentResult, VisionAgentResult


async def run_multi_agent_pipeline(
    report_path: Path,
    config: RunnerConfig,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run three independent whole-APK ReAct analyses, then invoke the Judge exactly once."""
    sample_started_at_utc = utc_now_iso()
    sample_started = time.perf_counter()
    deps = build_evidence_deps(report_path)

    print(f"\n[Multi-Agent] Processing sample: {report_path.stem}")
    print("-" * 60)
    print("Execution: 3 independent whole-APK ReAct agents -> 1 Judge")

    vision_prompt = build_vision_prompt(deps)
    ui_event_prompt = build_ui_event_prompt(deps)
    api_prompt = build_api_prompt(deps)

    analysis_started_at_utc = utc_now_iso()
    analysis_started = time.perf_counter()
    (
        (vision_result, vision_audit),
        (ui_event_result, ui_event_audit),
        (api_result, api_audit),
    ) = await asyncio.gather(
        run_stage(
            "Vision Agent",
            vision_agent,
            vision_prompt,
            isolated_agent_deps(deps),
            VisionAgentResult,
            config,
        ),
        run_stage(
            "UI/Event Agent",
            ui_event_agent,
            ui_event_prompt,
            isolated_agent_deps(deps),
            UIEventAgentResult,
            config,
        ),
        run_stage(
            "API Agent",
            api_agent,
            api_prompt,
            isolated_agent_deps(deps),
            APIAgentResult,
            config,
        ),
    )
    parallel_analysis_duration = time.perf_counter() - analysis_started

    evidence_audits = [vision_audit, ui_event_audit, api_audit]
    parallel_group_id = f"{deps.sample_hash}:parallel_evidence"
    for stage_audit in evidence_audits:
        stage_audit["parallel_group_id"] = parallel_group_id

    judge_prompt = build_judge_prompt(
        deps,
        vision_result,
        ui_event_result,
        api_result,
    )
    judge_started_at_utc = utc_now_iso()
    judge_started = time.perf_counter()
    judge_result = None
    judge_retry_audit: dict[str, Any] = {}
    try:
        judge_result = await run_agent_with_retry(
            judge_agent,
            judge_prompt,
            deps=deps,
            retries=config.agent_retries,
            initial_wait=config.retry_initial_wait,
            retry_audit=judge_retry_audit,
        )
        judge_output = model_from_result(judge_result, AndroidMalwareAnalysisOutput)
        final_report = judge_output.model_dump(mode="json", by_alias=True)
        final_report = normalize_final_report_apk_name(final_report, deps.sample_hash)
        judge_duration = time.perf_counter() - judge_started
        judge_finished_at_utc = utc_now_iso()
        judge_new_messages = result_method_value(judge_result, "new_messages")
        judge_audit = {
            "stage": "Judge Agent",
            "phase": "single_final_judgment",
            "execution_group": "single_judge",
            "depends_on_parallel_group_id": parallel_group_id,
            "status": "success",
            "started_at_utc": judge_started_at_utc,
            "finished_at_utc": judge_finished_at_utc,
            "duration_seconds": round(judge_duration, 3),
            "token_usage": extract_token_usage(judge_result),
            "model_request_count": extract_model_request_count(judge_result),
            "tool_call_count": count_tool_calls(judge_new_messages),
            "tool_call_count_complete": True,
            "retry_audit": judge_retry_audit,
            "prompt": judge_prompt,
            "new_messages": judge_new_messages,
            "all_messages": result_method_value(judge_result, "all_messages"),
            "raw_output": result_text(judge_result),
            "parsed_output": final_report,
        }
    except Exception as exc:
        judge_duration = time.perf_counter() - judge_started
        judge_finished_at_utc = utc_now_iso()
        error = safe_exception_text(exc, "Judge Agent execution failed")
        final_report = {
            "apk_name": deps.sample_hash,
            "is_malicious": False,
            "threat_category(Malicious family)": "Unknown",
            "confidence_score": 1,
            "reason": "The single Judge invocation failed, so no reliable malicious/benign verdict was produced.",
            "evidence_chain": [
                f"1. [Judge Failure] {error}",
                "2. [Unresolved] The three evidence agents completed, but their outputs were not successfully adjudicated.",
            ],
            "error": error,
        }
        judge_audit = {
            "stage": "Judge Agent",
            "phase": "single_final_judgment",
            "execution_group": "single_judge",
            "depends_on_parallel_group_id": parallel_group_id,
            "status": "failed",
            "started_at_utc": judge_started_at_utc,
            "finished_at_utc": judge_finished_at_utc,
            "duration_seconds": round(judge_duration, 3),
            "token_usage": extract_token_usage(judge_result),
            "model_request_count": extract_model_request_count(judge_result),
            "tool_call_count": 0,
            "tool_call_count_complete": True,
            "retry_audit": judge_retry_audit,
            "prompt": judge_prompt,
            "new_messages": result_method_value(judge_result, "new_messages"),
            "all_messages": result_method_value(judge_result, "all_messages"),
            "raw_output": error,
            "error": error,
            "parsed_output": final_report,
        }

    analysis_finished_at_utc = utc_now_iso()
    analysis_wall_time = time.perf_counter() - analysis_started
    evidence_cumulative_time = sum(
        float(stage.get("duration_seconds") or 0.0) for stage in evidence_audits
    )
    evidence_started = [
        stage.get("started_at_utc") for stage in evidence_audits if stage.get("started_at_utc")
    ]
    evidence_finished = [
        stage.get("finished_at_utc") for stage in evidence_audits if stage.get("finished_at_utc")
    ]
    analysis_execution = {
        "strategy": PIPELINE_EXECUTION_STRATEGY,
        "started_at_utc": analysis_started_at_utc,
        "finished_at_utc": analysis_finished_at_utc,
        "wall_time_seconds": round(analysis_wall_time, 3),
        "phases": {
            "parallel_independent_react": {
                "mode": "parallel",
                "agents": list(PARALLEL_EVIDENCE_AGENTS),
                "logical_runs_per_agent": 1,
                "parallel_group_id": parallel_group_id,
                "started_at_utc": min(evidence_started) if evidence_started else None,
                "finished_at_utc": max(evidence_finished) if evidence_finished else None,
                "wall_time_seconds": round(parallel_analysis_duration, 3),
                "cumulative_agent_time_seconds": round(evidence_cumulative_time, 3),
                "parallel_savings_seconds": round(
                    max(evidence_cumulative_time - parallel_analysis_duration, 0.0),
                    3,
                ),
            },
            "single_judge": {
                "mode": "serial_after_barrier",
                "agent": "judge_agent",
                "logical_run_count": 1,
                "depends_on_parallel_group_id": parallel_group_id,
                "started_at_utc": judge_started_at_utc,
                "finished_at_utc": judge_finished_at_utc,
                "wall_time_seconds": round(judge_duration, 3),
            },
        },
    }
    analysis_record = {
        "execution": analysis_execution,
        "stage_outputs": {
            "vision": serialize_value(vision_result),
            "ui_event": serialize_value(ui_event_result),
            "api": serialize_value(api_result),
        },
        "evidence_usage": build_evidence_usage(evidence_audits, deps.states),
        "stage_audits": evidence_audits,
        "judge_audit": judge_audit,
        "judge_output": final_report,
    }

    sample_finished_at_utc = utc_now_iso()
    sample_wall_time = time.perf_counter() - sample_started
    audit_report = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "document_type": "multi_agent_sample_audit",
        "runner": "pydantic_ai_multi_agent",
        "finished": "error" not in final_report,
        "sample_hash": deps.sample_hash,
        "input_report": llm_safe_report_ref(report_path),
        "execution": {
            **execution_descriptor(),
            "retry_policy": retry_policy_descriptor(config),
            "started_at_utc": sample_started_at_utc,
            "finished_at_utc": sample_finished_at_utc,
            "sample_wall_time_seconds": round(sample_wall_time, 3),
        },
        "models": {
            "vision": VISION_MODEL_NAME,
            "ui_event": TEXT_MODEL_NAME,
            "api": TEXT_MODEL_NAME,
            "judge": JUDGE_MODEL_NAME,
            "base_url": BASE_URL,
        },
        "source_counts": {
            "screens": len(deps.states),
            "semantic_states": len(deps.report.get("semantic_timeline", [])),
            "causal_events": len(deps.report.get("causal_events", [])),
            "sensitive_api_hits": (deps.report.get("trace_processing") or {}).get("total_sensitive_api_hits"),
        },
        "sample_context": sample_context(deps),
        "analysis": analysis_record,
        "judge_output": final_report,
    }
    verdict_text = (
        "Failed/Unknown"
        if final_report.get("error")
        else "Malicious" if final_report.get("is_malicious") else "Benign"
    )
    print(f"Judge verdict: {verdict_text}")
    return final_report, audit_report


AGENT_KEYS = {
    "Vision Agent": "vision_agent",
    "UI/Event Agent": "ui_event_agent",
    "API Agent": "api_agent",
    "Judge Agent": "judge_agent",
}


async def run_batch_task(
    report_source: str | Path = AGENT_REPORT_DIR,
    output_dir: str | Path = REASONING_OUTPUT_DIR,
    config: RunnerConfig | None = None,
) -> None:
    config = config or RunnerConfig()
    reports = collect_reports(report_source)
    if not reports:
        raise SystemExit(f"No fused JSON reports found: {report_source}")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    audit_dir = output_dir / "multi_agent_audits"
    trace_dir = output_dir / "multi_agent_traces"
    trace_log_path = output_dir / "llm_multi_agent_trace_full.md"
    analysis_reports_path = output_dir / "multi_agent_analysis_reports.json"
    context_save_path = output_dir / "all_apks_multi_agent_context.json"
    detailed_context_path = output_dir / "all_apks_multi_agent_detailed_context.json"
    timing_stats_path = output_dir / "timing_stats.json"

    session_started_at_utc = utc_now_iso()
    run_id = uuid.uuid4().hex
    run_metadata = {
        "run_id": run_id,
        "started_at_utc": session_started_at_utc,
        "input_source": str(report_source),
        "total_reports_input": len(reports),
    }

    source_index_by_sample = {path.stem: index for index, path in enumerate(reports)}

    def load_json_if_present(path: Path, default: Any) -> Any:
        try:
            return json_load(path) if path.is_file() else default
        except (OSError, json.JSONDecodeError):
            return default

    existing_public = load_json_if_present(analysis_reports_path, [])
    if not isinstance(existing_public, list):
        existing_public = []
    completed_reports = {
        str(item.get("apk_name")): item
        for item in existing_public
        if isinstance(item, dict)
        and item.get("status") == "success"
        and "is_malicious" in item
        and str(item.get("apk_name") or "") in source_index_by_sample
    }

    existing_context = load_json_if_present(context_save_path, [])
    if not isinstance(existing_context, list):
        existing_context = []
    existing_detailed_document = load_json_if_present(detailed_context_path, {})
    existing_detailed = (
        existing_detailed_document.get("records", [])
        if isinstance(existing_detailed_document, dict)
        else []
    )
    existing_timing_document = load_json_if_present(timing_stats_path, {})
    existing_timing = (
        existing_timing_document.get("details", [])
        if isinstance(existing_timing_document, dict)
        else []
    )

    print("=" * 60)
    print("Android Dynamic Evidence Multi-Agent System")
    print(f"Input reports: {report_source}")
    print(f"Output dir: {output_dir}")
    print(f"Reports found: {len(reports)}")
    print(f"Vision model: {VISION_MODEL_NAME}")
    print(f"Text model: {TEXT_MODEL_NAME}")
    print(f"Judge model: {JUDGE_MODEL_NAME}")
    print("=" * 60)

    completed_samples = set(completed_reports)
    all_reports: list[dict[str, Any]] = list(completed_reports.values())
    all_context_records: list[dict[str, Any]] = [
        item for item in existing_context
        if isinstance(item, dict) and str(item.get("apk_name") or "") in completed_samples
    ]
    all_detailed_context_records: list[dict[str, Any]] = [
        item for item in existing_detailed
        if isinstance(item, dict) and str(item.get("sample_hash") or "") in completed_samples
    ]
    timing_records: list[dict[str, Any]] = [
        item for item in existing_timing
        if isinstance(item, dict) and str(item.get("sample_hash") or "") in completed_samples
    ]
    audit_reports: list[dict[str, Any]] = []
    for sample_hash in completed_samples:
        audit_path = audit_dir / f"{sample_hash}.multi_agent_audit.json"
        audit = load_json_if_present(audit_path, None)
        if isinstance(audit, dict):
            audit_reports.append(audit)
    sample_trace_paths: list[Path] = [
        trace_dir / f"{source_index_by_sample[sample_hash]:05d}_{sample_hash}.md"
        for sample_hash in completed_samples
        if (trace_dir / f"{source_index_by_sample[sample_hash]:05d}_{sample_hash}.md").is_file()
    ]
    total_start = time.perf_counter()
    print(f"Resume: {len(completed_samples)} completed APK(s) will be skipped.")

    def current_classification_summary() -> dict[str, int]:
        return {
            "total_reports_input": len(reports),
            "processed_reports": len(all_reports),
            "malicious": sum(1 for item in all_reports if item.get("status") == "success" and item.get("is_malicious") is True),
            "benign": sum(1 for item in all_reports if item.get("status") == "success" and item.get("is_malicious") is False),
            "failed": sum(1 for item in all_reports if item.get("status") != "success"),
        }

    classification_summary = current_classification_summary()
    timing_summary = {
        **classification_summary,
        "batch_wall_time_seconds": 0.0,
        "call_statistics": aggregate_call_statistics(timing_records),
    }

    for index, report_path in enumerate(reports, start=1):
        if report_path.stem in completed_samples:
            print(f"\n[{index}/{len(reports)}] Skipping completed: {report_path.stem}")
            continue
        print(f"\n[{index}/{len(reports)}] Processing: {report_path.stem}")
        sample_started_at_utc = utc_now_iso()
        sample_start = time.perf_counter()
        try:
            final_report, audit_report = await run_multi_agent_pipeline(report_path, config)
        except Exception as exc:  # pragma: no cover - batch boundary
            duration = time.perf_counter() - sample_start
            final_report = {
                "apk_name": report_path.stem,
                "error": safe_exception_text(exc, "Sample pipeline failed"),
                "input_report": llm_safe_report_ref(report_path),
            }
            audit_report = {
                "schema_version": OUTPUT_SCHEMA_VERSION,
                "document_type": "multi_agent_sample_audit",
                "runner": "pydantic_ai_multi_agent",
                "finished": False,
                "sample_hash": report_path.stem,
                "input_report": llm_safe_report_ref(report_path),
                "execution": {
                    **execution_descriptor(),
                    "retry_policy": retry_policy_descriptor(config),
                    "started_at_utc": sample_started_at_utc,
                    "finished_at_utc": utc_now_iso(),
                    "sample_wall_time_seconds": round(duration, 3),
                },
                "analysis": None,
                "error": final_report["error"],
            }

        duration = time.perf_counter() - sample_start
        source_index = index - 1
        sample_status = (
            "success"
            if "error" not in final_report and "is_malicious" in final_report
            else "failed"
        )
        audit_report["run_id"] = run_id
        audit_report["source_index"] = source_index
        audit_report["status"] = sample_status
        public_report = public_final_report(
            final_report,
            report_path.stem,
            source_index,
            sample_status,
        )
        all_reports.append(public_report)
        all_context_records.append(evidence_agent_final_results_record(audit_report))
        all_detailed_context_records.append(detailed_context_record(audit_report))
        audit_reports.append(audit_report)
        sample_trace_path = trace_dir / f"{source_index:05d}_{report_path.stem}.md"
        atomic_write_text(
            sample_trace_path,
            render_sample_trace_markdown(audit_report, public_report),
        )
        sample_trace_paths.append(sample_trace_path)
        json_dump(audit_dir / f"{report_path.stem}.multi_agent_audit.json", audit_report)

        success_flag = sample_status == "success"
        timing_records.append(
            build_timing_record(
                report_path.stem,
                audit_report,
                duration,
                "success" if success_flag else "failed",
            )
        )

        classification_summary = current_classification_summary()
        timing_summary = {
            **classification_summary,
            "batch_wall_time_seconds": round(time.perf_counter() - total_start, 3),
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
        json_dump(
            analysis_reports_path,
            all_reports,
        )
        json_dump(
            context_save_path,
            all_context_records,
        )
        json_dump(
            detailed_context_path,
            build_collection_document(
                "all_apks_multi_agent_detailed_context",
                "records",
                all_detailed_context_records,
                classification_summary,
                run_metadata,
            ),
        )
        json_dump(
            timing_stats_path,
            build_collection_document(
                "multi_agent_timing_statistics",
                "details",
                timing_records,
                timing_summary,
                run_metadata,
            ),
        )

        verdict = public_report.get("is_malicious")
        verdict_text = (
            "Failed/Unknown"
            if sample_status != "success"
            else "Malicious" if verdict is True else "Benign"
        )
        print(f"Final Verdict: {verdict_text}")

    run_metadata["finished_at_utc"] = utc_now_iso()
    run_metadata["batch_wall_time_seconds"] = round(time.perf_counter() - total_start, 3)
    timing_summary["batch_wall_time_seconds"] = run_metadata["batch_wall_time_seconds"]
    all_reports.sort(key=lambda item: source_index_by_sample.get(str(item.get("apk_name") or ""), len(reports)))
    all_context_records.sort(key=lambda item: source_index_by_sample.get(str(item.get("apk_name") or ""), len(reports)))
    all_detailed_context_records.sort(
        key=lambda item: source_index_by_sample.get(str(item.get("sample_hash") or ""), len(reports))
    )
    timing_records.sort(key=lambda item: source_index_by_sample.get(str(item.get("sample_hash") or ""), len(reports)))
    audit_reports.sort(key=lambda item: source_index_by_sample.get(str(item.get("sample_hash") or ""), len(reports)))
    sample_trace_paths.sort(key=lambda path: path.name)
    json_dump(
        analysis_reports_path,
        all_reports,
    )
    json_dump(
        context_save_path,
        all_context_records,
    )
    json_dump(
        detailed_context_path,
        build_collection_document(
            "all_apks_multi_agent_detailed_context",
            "records",
            all_detailed_context_records,
            classification_summary,
            run_metadata,
        ),
    )
    json_dump(
        timing_stats_path,
        build_collection_document(
            "multi_agent_timing_statistics",
            "details",
            timing_records,
            timing_summary,
            run_metadata,
        ),
    )
    write_trace_document(
        trace_log_path,
        session_started_at_utc,
        sample_trace_paths,
        audit_reports,
    )

    print(f"\nAll tasks completed. Reports saved to: {analysis_reports_path}")
    print(f"Evidence Agent final results saved to: {context_save_path}")
    print(f"Detailed context saved to: {detailed_context_path}")
    print(f"Trace log saved to: {trace_log_path}")
    print(f"Per-sample traces saved to: {trace_dir}")
    print(f"Per-sample audits saved to: {audit_dir}")
    print(f"Statistics saved to: {timing_stats_path}")


TOKEN_SUMMARY_START = "<!-- AGENT_TOKEN_SUMMARY_START -->"


TOKEN_SUMMARY_END = "<!-- AGENT_TOKEN_SUMMARY_END -->"


