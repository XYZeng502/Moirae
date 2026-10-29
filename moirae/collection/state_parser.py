import hashlib
import json
from datetime import datetime
from pathlib import Path


STATE_TIME_FORMAT = "%Y-%m-%d_%H%M%S"
TRACE_EVENT_WINDOW_SECONDS = 2.0


def _clean_text(value):
    if value is None:
        return ""
    return str(value).strip()


def _unique_non_empty(values):
    seen = set()
    result = []
    for value in values:
        text = _clean_text(value)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _parse_state_time(tag):
    if not tag:
        return None
    try:
        return datetime.strptime(tag, STATE_TIME_FORMAT)
    except ValueError:
        return None


def _state_sort_key(path):
    tag = path.stem.removeprefix("state_")
    parsed = _parse_state_time(tag)
    if parsed:
        return parsed, path.name
    return datetime.min, path.name


def _event_sort_key(path):
    tag = path.stem.removeprefix("event_")
    parsed = _parse_state_time(tag)
    if parsed:
        return parsed, path.name
    return datetime.min, path.name


def _relative_or_absolute(path, base_dir):
    if not path:
        return None
    try:
        return str(path.relative_to(base_dir)).replace("\\", "/")
    except ValueError:
        return str(path)


def _package_from_activity(activity):
    if not activity:
        return ""
    return str(activity).split("/", 1)[0]


def _screen_for_state(state_path):
    tag = state_path.stem.removeprefix("state_")
    for suffix in (".png", ".jpg", ".jpeg"):
        candidate = state_path.with_name(f"screen_{tag}{suffix}")
        if candidate.exists():
            return candidate
    return None


def _view_signature(view):
    fields = (
        view.get("class"),
        view.get("resource_id"),
        view.get("text"),
        view.get("content_description"),
        view.get("package"),
        view.get("bounds"),
        view.get("clickable"),
        view.get("scrollable"),
        view.get("editable"),
    )
    return "|".join(_clean_text(field) for field in fields)


def _fallback_state_hash(views):
    joined = "\n".join(_view_signature(view) for view in views)
    return hashlib.md5(joined.encode("utf-8")).hexdigest()


def _compact_node(view):
    return {
        "temp_id": view.get("temp_id"),
        "parent": view.get("parent"),
        "children": view.get("children") or [],
        "package": _clean_text(view.get("package")),
        "class": _clean_text(view.get("class")),
        "resource_id": _clean_text(view.get("resource_id")),
        "text": _clean_text(view.get("text")),
        "content_description": _clean_text(view.get("content_description")),
        "bounds": view.get("bounds"),
        "enabled": bool(view.get("enabled")),
        "visible": bool(view.get("visible")),
        "clickable": bool(view.get("clickable")),
        "long_clickable": bool(view.get("long_clickable")),
        "scrollable": bool(view.get("scrollable")),
        "editable": bool(view.get("editable")),
        "checked": bool(view.get("checked")),
        "selected": bool(view.get("selected")),
        "focused": bool(view.get("focused")),
    }


def _compact_event_view(view):
    if not view:
        return None
    compact = _compact_node(view)
    compact.update(
        {
            "view_str": _clean_text(view.get("view_str")),
            "signature": _clean_text(view.get("signature")),
            "content_free_signature": _clean_text(view.get("content_free_signature")),
            "allowed_actions": view.get("allowed_actions") or [],
            "local_id": _clean_text(view.get("local_id")),
            "size": _clean_text(view.get("size")),
            "desc": _clean_text(view.get("desc")),
        }
    )
    return compact


def _interactable_label(view):
    label = (
        _clean_text(view.get("text"))
        or _clean_text(view.get("content_description"))
        or _clean_text(view.get("resource_id")).split("/")[-1]
        or _clean_text(view.get("class"))
    )
    return label


def _extract_interactable_elements(views):
    labels = []
    for view in views:
        if view.get("clickable") or view.get("long_clickable") or view.get("scrollable") or view.get("editable"):
            labels.append(_interactable_label(view))
    return _unique_non_empty(labels)


def _extract_semantic_texts(views):
    values = []
    for view in views:
        values.append(view.get("text"))
        values.append(view.get("content_description"))
    return _unique_non_empty(values)


def droidbot_has_native_states(droidbot_output_dir):
    states_dir = Path(droidbot_output_dir) / "states"
    return states_dir.exists() and any(states_dir.glob("state_*.json"))


def _state_reference(state_hash, state_by_hash):
    state = state_by_hash.get(state_hash)
    if not state:
        return {
            "ui_hash": _clean_text(state_hash),
            "state_id": None,
            "package": "",
            "foreground_activity": "",
            "screenshot_file": None,
            "state_file": None,
            "known": False,
        }
    return {
        "ui_hash": state["ui_hash"],
        "state_id": state["state_id"],
        "package": state["package"],
        "foreground_activity": state["foreground_activity"],
        "screenshot_file": state["screenshot_file"],
        "state_file": state["state_file"],
        "known": True,
    }


def _event_time_offset(tag, first_time):
    parsed_time = _parse_state_time(tag)
    if parsed_time and first_time:
        return round((parsed_time - first_time).total_seconds(), 2)
    return None


def _raw_event_time(raw_event):
    event = raw_event.get("event") or {}
    for source in (raw_event, event):
        for key in ("time", "timestamp"):
            value = source.get(key)
            if isinstance(value, (int, float)):
                return value
            if isinstance(value, str):
                try:
                    return float(value)
                except ValueError:
                    pass
    return None


def _trace_window(timestamp, seconds=TRACE_EVENT_WINDOW_SECONDS):
    if timestamp is None:
        return None
    return {
        "start": timestamp,
        "end": round(timestamp + seconds, 2),
        "duration": seconds,
    }


def _build_causal_events(droidbot_output_dir, state_by_hash, first_time):
    events_dir = droidbot_output_dir / "events"
    event_paths = sorted(events_dir.glob("event_*.json"), key=_event_sort_key)
    causal_events = []
    skipped_events = 0

    for event_path in event_paths:
        try:
            raw_event = json.loads(event_path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            skipped_events += 1
            continue

        event = raw_event.get("event") or {}
        tag = _clean_text(raw_event.get("tag")) or event_path.stem.removeprefix("event_")
        timestamp = _event_time_offset(tag, first_time)
        raw_timestamp = _raw_event_time(raw_event)
        start_state = _clean_text(raw_event.get("start_state"))
        stop_state = _clean_text(raw_event.get("stop_state"))
        view = event.get("view") or {}
        unchanged_state = bool(start_state and start_state == stop_state)
        event_type = _clean_text(event.get("event_type"))

        causal_events.append(
            {
                "event_id": len(causal_events) + 1,
                "timestamp": timestamp,
                "raw_timestamp": raw_timestamp,
                "captured_at": tag,
                "event_type": event_type,
                "direction": _clean_text(event.get("direction")),
                "x": event.get("x"),
                "y": event.get("y"),
                "event_str": _clean_text(raw_event.get("event_str")),
                "event_file": _relative_or_absolute(event_path, droidbot_output_dir),
                "start_state": _state_reference(start_state, state_by_hash),
                "stop_state": _state_reference(stop_state, state_by_hash),
                "start_state_hash": start_state,
                "stop_state_hash": stop_state,
                "changed_state": bool(start_state and stop_state and start_state != stop_state),
                "unchanged_state": unchanged_state,
                "silent_payload_candidate": unchanged_state,
                "trace_window": _trace_window(timestamp),
                "raw_trace_window": _trace_window(raw_timestamp),
                "view": _compact_event_view(view),
                "view_text": _clean_text(view.get("text")),
                "view_content_description": _clean_text(view.get("content_description")),
                "view_resource_id": _clean_text(view.get("resource_id")),
                "view_class": _clean_text(view.get("class")),
                "view_package": _clean_text(view.get("package")),
                "view_bounds": view.get("bounds"),
                "allowed_actions": view.get("allowed_actions") or [],
            }
        )

    return causal_events, len(event_paths), skipped_events


def _build_transition_graph(semantic_timeline, causal_events):
    nodes = [
        {
            "ui_hash": state["ui_hash"],
            "state_id": state["state_id"],
            "state_type": state["state_type"],
            "package": state["package"],
            "foreground_activity": state["foreground_activity"],
            "screenshot_file": state["screenshot_file"],
            "state_file": state["state_file"],
        }
        for state in semantic_timeline
    ]
    edges = [
        {
            "event_id": event["event_id"],
            "from": event["start_state_hash"],
            "to": event["stop_state_hash"],
            "event_type": event["event_type"],
            "view_text": event["view_text"],
            "view_content_description": event["view_content_description"],
            "view_resource_id": event["view_resource_id"],
            "view_class": event["view_class"],
            "changed_state": event["changed_state"],
            "unchanged_state": event["unchanged_state"],
            "trace_window": event["trace_window"],
            "raw_trace_window": event["raw_trace_window"],
        }
        for event in causal_events
    ]
    return {
        "nodes": nodes,
        "edges": edges,
    }


def build_droidbot_semantic_stream(droidbot_output_dir, output_dir, target_package):
    droidbot_output_dir = Path(droidbot_output_dir)
    output_dir = Path(output_dir)
    states_dir = droidbot_output_dir / "states"
    state_paths = sorted(states_dir.glob("state_*.json"), key=_state_sort_key)
    if not state_paths:
        raise FileNotFoundError(f"No DroidBot state_*.json files found in {states_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    first_time = None
    seen_hashes = set()
    semantic_timeline = []
    state_by_hash = {}
    duplicate_count = 0

    for state_path in state_paths:
        try:
            state = json.loads(state_path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            continue

        views = state.get("views") or []
        tag = _clean_text(state.get("tag")) or state_path.stem.removeprefix("state_")
        parsed_time = _parse_state_time(tag)
        if first_time is None and parsed_time:
            first_time = parsed_time

        ui_hash = _clean_text(state.get("state_str")) or _fallback_state_hash(views)
        if ui_hash in seen_hashes:
            duplicate_count += 1
            continue
        seen_hashes.add(ui_hash)

        foreground_activity = _clean_text(state.get("foreground_activity"))
        current_package = _package_from_activity(foreground_activity)
        if not current_package:
            packages = _unique_non_empty(view.get("package") for view in views)
            current_package = packages[0] if packages else ""
        state_type = "INTERNAL" if target_package and current_package == target_package else "EXTERNAL"
        screenshot_path = _screen_for_state(state_path)

        timestamp = None
        if parsed_time and first_time:
            timestamp = round((parsed_time - first_time).total_seconds(), 2)

        state_info = {
            "state_id": len(semantic_timeline) + 1,
            "timestamp": timestamp,
            "captured_at": tag,
            "state_type": state_type,
            "package": current_package,
            "view_packages": _unique_non_empty(view.get("package") for view in views),
            "foreground_activity": foreground_activity,
            "activity_stack": state.get("activity_stack") or [],
            "ui_hash": ui_hash,
            "content_free_hash": _clean_text(state.get("state_str_content_free")),
            "state_file": _relative_or_absolute(state_path, droidbot_output_dir),
            "screenshot_file": _relative_or_absolute(screenshot_path, droidbot_output_dir),
            "width": state.get("width"),
            "height": state.get("height"),
            "view_count": len(views),
            "extracted_text": _extract_semantic_texts(views),
            "interactable_elements": _extract_interactable_elements(views),
            "ui_nodes": [_compact_node(view) for view in views],
        }
        semantic_timeline.append(state_info)
        state_by_hash[ui_hash] = state_info

    causal_events, total_droidbot_events, skipped_droidbot_events = _build_causal_events(
        droidbot_output_dir=droidbot_output_dir,
        state_by_hash=state_by_hash,
        first_time=first_time,
    )
    transition_graph = _build_transition_graph(semantic_timeline, causal_events)

    report = {
        "source": "droidbot_native_states",
        "event_source": "droidbot_native_events",
        "target_package": target_package,
        "droidbot_output_dir": str(droidbot_output_dir),
        "total_droidbot_states": len(state_paths),
        "total_unique_states": len(semantic_timeline),
        "duplicates_removed": duplicate_count,
        "total_droidbot_events": total_droidbot_events,
        "total_causal_events": len(causal_events),
        "skipped_droidbot_events": skipped_droidbot_events,
        "trace_event_window_seconds": TRACE_EVENT_WINDOW_SECONDS,
        "semantic_timeline": semantic_timeline,
        "causal_events": causal_events,
        "state_transition_graph": transition_graph,
    }

    report_path = output_dir / "xml_semantic_stream.json"
    report_path.write_text(json.dumps(report, indent=4, ensure_ascii=False), encoding="utf-8")
    return report_path
