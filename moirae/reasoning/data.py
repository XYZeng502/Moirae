"""Data components extracted from the original Moirae runner."""
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from ..evidence.tools import AndroidEvidenceDeps, detect_evidence_path_config, llm_safe_report_ref, resolve_droidbot_output_dir
from ..config import DATASET_ROOT


def collect_reports(path: str | Path) -> list[Path]:
    path = Path(path)
    if path.is_file():
        return [path] if path.suffix.lower() == ".json" else []
    if path.is_dir():
        return sorted(path.glob("*.json"))
    return []


def json_load(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8", errors="ignore"))


def atomic_write_chunks(path: str | Path, chunks) -> None:
    """Replace an output file atomically so readers never observe a partial record."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            for chunk in chunks:
                handle.write(str(chunk))
            temporary_path = Path(handle.name)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def atomic_write_text(path: str | Path, content: str) -> None:
    atomic_write_chunks(path, [content])


def json_dump(path: str | Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def sort_key(item: dict[str, Any]) -> tuple[float, str]:
    timestamp = item.get("timestamp")
    if timestamp is None:
        return (float("inf"), item.get("captured_at") or "")
    return (float(timestamp), item.get("captured_at") or "")


def unique_non_empty(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def screen_for_state_file(state_path: Path) -> Path | None:
    tag = state_path.stem.removeprefix("state_")
    for suffix in (".png", ".jpg", ".jpeg"):
        candidate = state_path.with_name(f"screen_{tag}{suffix}")
        if candidate.exists():
            return candidate
    return None


def raw_state_to_analysis_state(
    raw_state: dict[str, Any],
    state_path: Path,
    screenshot_path: Path | None,
    semantic_by_hash: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    ui_hash = str(raw_state.get("state_str") or "")
    semantic_state = dict(semantic_by_hash.get(ui_hash) or {})
    views = raw_state.get("views") or []
    tag = str(raw_state.get("tag") or state_path.stem.removeprefix("state_"))

    if not semantic_state:
        foreground_activity = str(raw_state.get("foreground_activity") or "")
        current_package = foreground_activity.split("/", 1)[0] if foreground_activity else ""
        if not current_package:
            packages = unique_non_empty(view.get("package") for view in views)
            current_package = packages[0] if packages else ""
        semantic_state = {
            "state_id": None,
            "timestamp": None,
            "captured_at": tag,
            "state_type": "UNKNOWN",
            "package": current_package,
            "view_packages": unique_non_empty(view.get("package") for view in views),
            "foreground_activity": foreground_activity,
            "activity_stack": raw_state.get("activity_stack") or [],
            "ui_hash": ui_hash,
            "content_free_hash": str(raw_state.get("state_str_content_free") or ""),
            "width": raw_state.get("width"),
            "height": raw_state.get("height"),
            "view_count": len(views),
            "extracted_text": unique_non_empty(
                value
                for view in views
                for value in (view.get("text"), view.get("content_description"))
            ),
            "interactable_elements": unique_non_empty(
                view.get("text")
                or view.get("content_description")
                or str(view.get("resource_id") or "").split("/")[-1]
                or view.get("class")
                for view in views
                if view.get("clickable") or view.get("long_clickable") or view.get("scrollable") or view.get("editable")
            ),
            "ui_nodes": views,
        }

    semantic_state["raw_state_file"] = str(state_path)
    semantic_state["screenshot_file"] = str(screenshot_path) if screenshot_path else semantic_state.get("screenshot_file")
    semantic_state["captured_at"] = tag
    semantic_state["timestamp"] = None
    semantic_state["ui_hash"] = ui_hash or semantic_state.get("ui_hash")
    return semantic_state


def load_screen_states(
    report: dict[str, Any],
    droidbot_output_dir: str | Path,
) -> list[dict[str, Any]]:
    droidbot_output_dir = Path(droidbot_output_dir)
    states_dir = droidbot_output_dir / "states"
    semantic_by_hash = {
        state.get("ui_hash"): state
        for state in report.get("semantic_timeline", [])
        if state.get("ui_hash")
    }
    raw_states: list[dict[str, Any]] = []

    if states_dir.exists():
        for state_path in sorted(states_dir.glob("state_*.json"), key=lambda path: path.name):
            try:
                raw_state = json_load(state_path)
            except (OSError, json.JSONDecodeError):
                continue
            screenshot_path = screen_for_state_file(state_path)
            if not screenshot_path:
                continue
            raw_states.append(raw_state_to_analysis_state(raw_state, state_path, screenshot_path, semantic_by_hash))

    if raw_states:
        return sorted(raw_states, key=sort_key)
    return sorted(report.get("semantic_timeline", []), key=sort_key)


def build_evidence_deps(report_path: str | Path) -> AndroidEvidenceDeps:
    report_path = Path(report_path)
    report = json_load(report_path)
    paths = detect_evidence_path_config(report_path, DATASET_ROOT)
    droidbot_output_dir = resolve_droidbot_output_dir(
        report,
        report_path.stem,
        paths,
    )
    states = load_screen_states(report, droidbot_output_dir)
    return AndroidEvidenceDeps(
        sample_hash=report_path.stem,
        report_path=llm_safe_report_ref(report_path),
        report=report,
        states=states,
        droidbot_output_dir=str(droidbot_output_dir),
        paths=paths,
    )


def sample_context(
    deps: AndroidEvidenceDeps,
    *,
    include_screen_summary: bool = True,
    include_event_summary: bool = True,
    include_trace_summary: bool = True,
) -> str:
    trace_processing = deps.report.get("trace_processing") or {}
    context = (
        f"Sample hash: {deps.sample_hash}\n"
        f"Target package: {deps.report.get('target_package')}\n"
        f"Input evidence report: {deps.report_path}\n"
    )
    if include_screen_summary:
        context += f"Available DroidBot screens: {len(deps.states)}\n"
    if include_event_summary:
        context += (
            f"Unique semantic states: {len(deps.report.get('semantic_timeline', []))}\n"
            f"Causal events: {len(deps.report.get('causal_events', []))}\n"
        )
    if include_trace_summary:
        context += (
            f"Trace status: {trace_processing.get('final_trace_status')}\n"
            f"Sensitive API hits: {trace_processing.get('total_sensitive_api_hits')}\n"
        )
    return context


