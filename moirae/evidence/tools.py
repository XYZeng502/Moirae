"""Role-scoped evidence models, pagination, and ReAct tools."""
import inspect
import json
import mimetypes
import os
import re
from dataclasses import dataclass, field
from functools import wraps
from io import BytesIO
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, SerializerFunctionWrapHandler, model_serializer
from pydantic_ai import BinaryContent, RunContext, ToolReturn

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None


from ..config import DATASET_ROOT as DEFAULT_DATASET_ROOT


def react_logger(func):
    """Print action/observation blocks for ReAct-style trace readability."""

    def _log(message: str) -> None:
        if os.getenv("LLM_REASONING_TOOL_LOGS", "1").strip().lower() not in {"0", "false", "no", "off"}:
            print(message)

    def _visible_args(args, kwargs):
        visible_kwargs = {key: value for key, value in kwargs.items() if key != "ctx"}
        if args:
            visible_kwargs["_positional_count"] = max(len(args) - 1, 0)
        return visible_kwargs

    def _format_result(result):
        return_value = getattr(result, "return_value", result)
        if isinstance(return_value, BaseModel):
            text = return_value.model_dump_json(indent=2)
        elif hasattr(return_value, "model_dump_json"):
            text = return_value.model_dump_json(indent=2)
        elif hasattr(return_value, "model_dump"):
            text = json.dumps(return_value.model_dump(mode="json"), indent=2, ensure_ascii=False)
        else:
            try:
                text = json.dumps(return_value, indent=2, ensure_ascii=False)
            except TypeError:
                text = str(return_value)
        if len(text) > 3000:
            text = text[:1000] + f"\n... ({len(text) - 1000} characters hidden) ..."
        return text

    if inspect.iscoroutinefunction(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            _log(f"\n<action>\nCalling Tool: {func.__name__}\nArguments: {_visible_args(args, kwargs)}\n</action>")
            try:
                result = await func(*args, **kwargs)
                _log(f"\n<observation>\n{_format_result(result)}\n</observation>")
                return result
            except Exception as exc:
                _log(f"\n<observation>\nTool execution exception: {exc}\n</observation>")
                raise RuntimeError(
                    safe_exception_text(exc, f"Tool {func.__name__} failed")
                ) from None

        return async_wrapper

    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        _log(f"\n<action>\nCalling Tool: {func.__name__}\nArguments: {_visible_args(args, kwargs)}\n</action>")
        try:
            result = func(*args, **kwargs)
            _log(f"\n<observation>\n{_format_result(result)}\n</observation>")
            return result
        except Exception as exc:
            _log(f"\n<observation>\nTool execution exception: {exc}\n</observation>")
            raise RuntimeError(
                safe_exception_text(exc, f"Tool {func.__name__} failed")
            ) from None

    return sync_wrapper


# ================= Dependencies =================
@dataclass(frozen=True)
class AndroidEvidencePathConfig:
    """Centralized dataset path layout for one APK sample.

    The category values are defaults only. The caller can pass another config
    through AndroidEvidenceDeps when analyzing another malware family.
    """

    dataset_root: Path = DEFAULT_DATASET_ROOT
    split: str = "malware"
    droidbot_family: str = "Adware"
    xml_family: str = "Adware"
    fused_api_family: str = "Adware"

    @property
    def droidbot_out_root(self) -> Path:
        return self.dataset_root / "droidbot_out" / self.split

    @property
    def xml_states_root(self) -> Path:
        return self.dataset_root / "xml_states" / "droidbot" / self.split

    @property
    def fused_api_root(self) -> Path:
        return self.dataset_root / "agent_workspace" / self.split

    def _family_dir(self, root: Path, family: str) -> Path:
        """Apply a family level only to malware; benign is stored directly."""
        if self.split.casefold() == "benign":
            return root
        return root / family

    @property
    def fused_api_dir(self) -> Path:
        return self._family_dir(self.fused_api_root, self.fused_api_family)

    def droidbot_sample_dir(self, apk_hash: str) -> Path:
        return self._family_dir(self.droidbot_out_root, self.droidbot_family) / apk_hash

    def states_dir(self, apk_hash: str) -> Path:
        return self.droidbot_sample_dir(apk_hash) / "states"

    def events_dir(self, apk_hash: str) -> Path:
        return self.droidbot_sample_dir(apk_hash) / "events"

    def xml_dir(self, apk_hash: str) -> Path:
        return self._family_dir(self.xml_states_root, self.xml_family) / apk_hash

    def fused_api_report(self, apk_hash: str) -> Path:
        return self.fused_api_dir / f"{apk_hash}.json"

    def as_dict(self, apk_hash: str) -> dict[str, str]:
        """Return LLM-safe evidence references without dataset class folders."""
        return {
            "states_dir": f"sample:{apk_hash}/states",
            "events_dir": f"sample:{apk_hash}/events",
            "xml_dir": f"sample:{apk_hash}/xml_states",
            "fused_api_dir": "sample:fused_api_reports",
            "fused_api_report": f"sample:{apk_hash}/fused_api_report.json",
        }


def detect_evidence_path_config(
    report_path: str | Path,
    dataset_root: str | Path = DEFAULT_DATASET_ROOT,
) -> AndroidEvidencePathConfig:
    """Detect benign or malware/family layout from a fused report location.

    Supported layouts:
      agent_workspace/benign/<hash>.json
      agent_workspace/malware/<family>/<hash>.json
    """
    report_path = Path(report_path)
    dataset_root = Path(dataset_root)
    parts = report_path.parts
    workspace_index = next(
        (
            index
            for index, part in enumerate(parts)
            if part.casefold() == "agent_workspace"
        ),
        None,
    )
    if workspace_index is not None:
        category_parts = parts[workspace_index + 1 :]
        if category_parts and category_parts[0].casefold() == "benign":
            return AndroidEvidencePathConfig(
                dataset_root=dataset_root,
                split="benign",
                droidbot_family="benign",
                xml_family="benign",
                fused_api_family="benign",
            )
        if len(category_parts) >= 2 and category_parts[0].casefold() == "malware":
            family = category_parts[1]
            return AndroidEvidencePathConfig(
                dataset_root=dataset_root,
                split="malware",
                droidbot_family=family,
                xml_family=family,
                fused_api_family=family,
            )

    sample_hash = report_path.stem
    benign_report = dataset_root / "agent_workspace" / "benign" / f"{sample_hash}.json"
    if benign_report.exists():
        return AndroidEvidencePathConfig(
            dataset_root=dataset_root,
            split="benign",
            droidbot_family="benign",
            xml_family="benign",
            fused_api_family="benign",
        )

    malware_root = dataset_root / "agent_workspace" / "malware"
    malware_matches = list(malware_root.glob(f"*/{sample_hash}.json")) if malware_root.exists() else []
    if len(malware_matches) == 1:
        family = malware_matches[0].parent.name
        return AndroidEvidencePathConfig(
            dataset_root=dataset_root,
            split="malware",
            droidbot_family=family,
            xml_family=family,
            fused_api_family=family,
        )

    return AndroidEvidencePathConfig(dataset_root=dataset_root)


def resolve_droidbot_output_dir(
    report: dict[str, Any],
    sample_hash: str,
    paths: AndroidEvidencePathConfig,
) -> Path:
    """Prefer the detected local layout, then a valid path recorded in JSON."""
    detected = paths.droidbot_sample_dir(sample_hash)
    if detected.exists():
        return detected

    reported_value = str(report.get("droidbot_output_dir") or "").strip()
    if reported_value:
        reported = Path(reported_value)
        if reported.exists():
            return reported
    return detected


@dataclass
class AndroidEvidenceDeps:
    """Runtime evidence supplied by the caller.

    The caller is responsible for reading the fused JSON report, loading DroidBot
    states/screens, and passing those objects into this deps object.
    """

    sample_hash: str
    report_path: str
    report: dict[str, Any]
    states: list[dict[str, Any]]
    droidbot_output_dir: str | None = None
    paths: AndroidEvidencePathConfig = field(default_factory=AndroidEvidencePathConfig)
    visited_screens: set[int] = field(default_factory=set)
    observation_counter: int = 0


# ================= Model Definitions =================
def _drop_empty_values(value: Any) -> Any:
    """Remove JSON fields that carry no evidence while preserving False and 0."""
    if isinstance(value, dict):
        compact = {}
        for key, item in value.items():
            compact_item = _drop_empty_values(item)
            if compact_item not in (None, "", [], {}):
                compact[key] = compact_item
        return compact
    if isinstance(value, list):
        return [
            compact_item
            for item in value
            if (compact_item := _drop_empty_values(item)) not in (None, "", [], {})
        ]
    return value


class ToolBaseResult(BaseModel):
    """Internal result envelope serialized as evidence-only JSON for the LLM."""
    observation_id: int
    ok: bool
    summary: str
    error: str | None = None

    @model_serializer(mode="wrap")
    def _serialize_for_llm(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload = sanitize_llm_payload(_drop_empty_values(handler(self)))
        # The tool protocol and execution trace already identify the observation.
        payload.pop("observation_id", None)
        payload.pop("tool", None)
        payload.pop("ok", None)
        if self.ok:
            payload.pop("summary", None)
            payload.pop("error", None)
        elif payload.get("error"):
            payload.pop("summary", None)
        return payload

# ================= Navigation and global inventory results =================
class ScreenSummaryItem(BaseModel):
    screen_index: int
    captured_at: str | None = None
    package: str | None = None
    foreground_activity: str | None = None

class ScreenListResult(ToolBaseResult):
    tool: Literal["LIST_SCREENS"] = "LIST_SCREENS"
    screens_total: int
    screens: list[ScreenSummaryItem] = Field(default_factory=list)
    next_start_index: int | None = None


class EventSummaryItem(BaseModel):
    event_id: int | None = None
    timestamp: float | None = None
    event_type: str | None = None
    action: str | None = None
    start_state_hash: str | None = None
    stop_state_hash: str | None = None
    trace_status: str | None = None
    api_calls_total: int = 0


class EventListResult(ToolBaseResult):
    tool: Literal["LIST_EVENTS"] = "LIST_EVENTS"
    events_total: int
    events: list[EventSummaryItem] = Field(default_factory=list)
    next_event_offset: int | None = None


class UIEventSummaryItem(BaseModel):
    """Event inventory item that intentionally excludes all API/trace metadata."""

    event_id: int | None = None
    timestamp: float | None = None
    event_type: str | None = None
    action: str | None = None
    start_state_hash: str | None = None
    stop_state_hash: str | None = None


class UIEventListResult(ToolBaseResult):
    tool: Literal["LIST_UI_EVENTS"] = "LIST_UI_EVENTS"
    events_total: int
    events: list[UIEventSummaryItem] = Field(default_factory=list)
    next_event_offset: int | None = None


class NextScreenResult(ToolBaseResult):
    tool: Literal["NEXT_SCREEN"] = "NEXT_SCREEN"
    next_screen_index: int | None = None
    done: bool
    captured_at: str | None = None
    package: str | None = None
    foreground_activity: str | None = None


class FirstRelatedEventResult(ToolBaseResult):
    tool: Literal["FIRST_RELATED_EVENT"] = "FIRST_RELATED_EVENT"
    screen_index: int
    has_related_event: bool
    event_id: int | None = None

# ================= Visual and UI state results =================
class InspectScreenResult(ToolBaseResult):
    tool: Literal["INSPECT_SCREEN"] = "INSPECT_SCREEN"
    screen_index: int | None = None
    captured_at: str | None = None
    package: str | None = None
    foreground_activity: str | None = None
    image_ref: str | None = None

class UIStateNode(BaseModel):
    class_name: str | None = Field(default=None, alias="class")
    resource_id: str | None = None
    text: str | None = None
    content_description: str | None = None
    package: str | None = None
    bounds: list[int] | None = Field(default=None, description="Format: [x1, y1, x2, y2]")
    clickable: bool | None = None
    scrollable: bool | None = None
    editable: bool | None = None

class UIStateSnapshot(BaseModel):
    state_type: str | None = None
    package: str | None = None
    foreground_activity: str | None = None
    activity_stack: list[str] = Field(default_factory=list)
    ui_hash: str | None = None
    text_fallback: list[str] = Field(default_factory=list)
    ui_nodes: list[UIStateNode] = Field(default_factory=list)

class UIStateResult(ToolBaseResult):
    tool: Literal["READ_UI_STATE"] = "READ_UI_STATE"
    screen_index: int | None = None
    state_ref: str | None = None
    ui_state: UIStateSnapshot | None = None

# ================= Interaction events and native API trace results =================
class UIEventRecord(BaseModel):
    """Isolated model for UI actions and causal state transitions only."""
    event_id: int | None = None
    timestamp: float | None = None
    event_type: str | None = None
    relation_to_screen: Literal["incoming", "outgoing", "self"] | None = None
    action: str | None = None
    event_str: str | None = None
    start_state_hash: str | None = None
    stop_state_hash: str | None = None
    changed_state: bool | None = None
    unchanged_state: bool | None = None
    silent_payload_candidate: bool | None = None
    view_text: str | None = None
    view_content_description: str | None = None
    view_resource_id: str | None = None
    view_class: str | None = None
    view_package: str | None = None
    view_bounds: list[int] | None = None

class RelatedEventsResult(ToolBaseResult):
    tool: Literal["READ_RELATED_EVENTS"] = "READ_RELATED_EVENTS"
    screen_index: int | None = None
    events_total: int = 0
    events: list[UIEventRecord] = Field(default_factory=list)
    next_event_offset: int | None = None

class NativeTraceRecord(BaseModel):
    event_id: int | None = None
    trace_window: dict[str, float] | None = None
    trace_status: str | None = None
    api_calls_total: int = 0
    api_offset: int = 0
    native_behavior_summary: list[Any] = Field(default_factory=list)
    next_api_offset: int | None = None

class APICallsResult(ToolBaseResult):
    tool: Literal["READ_API_CALLS"] = "READ_API_CALLS"
    evidence_status: Literal[
        "available",
        "empty",
        "partial",
        "unavailable",
        "invalid"
    ] = "empty"
    events_total: int = 0
    event_ids: list[int] = Field(default_factory=list)
    trace_statuses: dict[str, list[int]] = Field(default_factory=dict)
    api_calls: list[NativeTraceRecord] = Field(
        default_factory=list
    )
    next_event_offset: int | None = None

class RawEventRecord(BaseModel):
    """Fallback container for unparsed raw JSON event logs."""
    event_id: int | None = None
    raw_event_json: dict[str, Any] | None = None
    original_size_chars: int = 0
    truncated: bool = False


class RawEventResult(ToolBaseResult):
    tool: Literal["READ_RAW_EVENT"] = "READ_RAW_EVENT"
    events_total: int = 0
    raw_events: list[RawEventRecord] = Field(default_factory=list)
    truncated: bool = False

# ================= Core Helper Functions =================
def _next_observation_id(deps: AndroidEvidenceDeps) -> int:
    deps.observation_counter += 1
    return deps.observation_counter


def _sort_key(item: dict[str, Any]) -> tuple[float, str]:
    timestamp = _float_or_none(item.get("timestamp"))
    return (
        timestamp if timestamp is not None else float("inf"),
        _text_or_none(item.get("captured_at")) or "",
    )


def _state_at(deps: AndroidEvidenceDeps, screen_index: int | None) -> dict[str, Any] | None:
    if screen_index is None or screen_index < 0 or screen_index >= len(deps.states):
        return None
    return deps.states[screen_index]


def _result(
    deps: AndroidEvidenceDeps,
    result_cls: type[ToolBaseResult],
    ok: bool,
    summary: str,
    error: str | None = None,
    **kwargs: Any,
) -> ToolBaseResult:
    return result_cls(
        observation_id=_next_observation_id(deps),
        ok=ok,
        summary=summary,
        error=error,
        **kwargs,
    )


def _error_result(
    deps: AndroidEvidenceDeps,
    result_cls: type[ToolBaseResult],
    message: str,
    **kwargs: Any,
) -> ToolBaseResult:
    return _result(
        deps=deps,
        result_cls=result_cls,
        ok=False,
        summary=message,
        error=message,
        **kwargs,
    )


def _resolve_droidbot_file(deps: AndroidEvidenceDeps, relative_or_absolute: str | None) -> Path | None:
    if not relative_or_absolute:
        return None
    path = Path(relative_or_absolute)
    if path.is_absolute():
        return path
    base_dir = Path(
        deps.droidbot_output_dir
        or deps.report.get("droidbot_output_dir")
        or deps.paths.droidbot_sample_dir(deps.sample_hash)
    )
    return base_dir / path


def _json_load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))

def _looks_like_path(value: str) -> bool:
    candidate = value.strip()
    if not candidate or "\n" in candidate or "\r" in candidate or len(candidate) > 1_024:
        return False
    # URLs and Android/content URIs are behavioral evidence, not local paths.
    if re.match(r"^[a-z][a-z0-9+.-]*://", candidate, flags=re.IGNORECASE):
        return False

    normalized = candidate.replace("\\", "/").lower()
    windows_absolute = bool(re.match(r"^[a-z]:[\\/]", candidate, flags=re.IGNORECASE))
    has_path_separator = "/" in normalized or "\\" in candidate
    return (
        windows_absolute
        or "\\" in candidate
        or any(
            marker in normalized
            for marker in (
                "/dataset/",
                "/agent_workspace/",
                "/droidbot_out/",
                "/xml_states/",
                "/states/",
                "/events/",
            )
        )
        or (
            has_path_separator
            and normalized.endswith((".json", ".jpg", ".jpeg", ".png", ".trace", ".mp4"))
        )
    )


def _public_file_ref(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    if not _looks_like_path(text):
        return text

    normalized = text.replace("\\", "/")
    basename = normalized.rstrip("/").split("/")[-1]
    if not basename:
        return "sample:evidence"

    parent = normalized.rstrip("/").split("/")[-2] if "/" in normalized.rstrip("/") else ""
    if parent in {"states", "events", "xml_states"}:
        return f"{parent}/{basename}"
    # A directory basename may itself be a dataset class/family label.  Do not
    # expose it when there is no safe file-level reference to retain.
    if "." not in basename:
        return "sample:evidence"
    return basename


def llm_safe_report_ref(path: str | Path) -> str:
    """Return the report identifier exposed by tools/prompts, never its host path."""
    return f"sample:{Path(path).stem}/fused_api_report.json"


def llm_safe_file_ref(value: Any) -> str | None:
    """Return a file reference without dataset root or classification folders."""
    return _public_file_ref(value)


_QUOTED_WINDOWS_PATH_RE = re.compile(
    r"(?P<quote>[\"'])(?P<path>[A-Za-z]:[\\/][^\"'\r\n]+)(?P=quote)"
)
_UNQUOTED_WINDOWS_PATH_RE = re.compile(
    r"\b[A-Za-z]:[\\/][^\"'\r\n]+"
)
_DATASET_PATH_FRAGMENT_RE = re.compile(
    r"(?i)(?:/(?:[^\s\"'<>|]+/)*)?"
    r"(?:dataset|agent_workspace|droidbot_out|xml_states)[\\/]"
    r"[^\s\"'<>|,;)\]}]+"
)
_BEHAVIOR_URI_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"']+"
)


def sanitize_llm_text(value: Any) -> str:
    """Remove host/dataset paths from arbitrary text before it reaches an LLM.

    Whole file references retain only a safe file/state reference. Embedded
    paths (commonly found in exception messages) are replaced completely.
    Behavioral URLs and Android/content URIs are intentionally preserved.
    """
    text = str(value)
    original = text
    protected_uris: list[str] = []

    def protect_uri(match: re.Match[str]) -> str:
        protected_uris.append(match.group(0))
        return f"<behavior_uri_{len(protected_uris) - 1}>"

    text = _BEHAVIOR_URI_RE.sub(protect_uri, text)
    text = _QUOTED_WINDOWS_PATH_RE.sub("<local_evidence_path>", text)
    text = _UNQUOTED_WINDOWS_PATH_RE.sub("<local_evidence_path>", text)
    text = _DATASET_PATH_FRAGMENT_RE.sub("<local_evidence_path>", text)
    if not protected_uris and text == original and _looks_like_path(text):
        return _public_file_ref(text) or "sample:evidence"
    for index, uri in enumerate(protected_uris):
        text = text.replace(f"<behavior_uri_{index}>", uri)
    return text


def safe_exception_text(exc: BaseException, context: str = "Operation failed") -> str:
    """Return an LLM-safe error without serializing the exception message."""
    return f"{context} ({type(exc).__name__})."


def sanitize_llm_payload(value: Any) -> Any:
    """Recursively sanitize values that may be serialized into LLM context."""
    if isinstance(value, dict):
        return {key: sanitize_llm_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_llm_payload(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_llm_payload(item) for item in value]
    if isinstance(value, str):
        return sanitize_llm_text(value)
    return value


# Private compatibility alias for existing internal callers.
_sanitize_llm_payload = sanitize_llm_payload


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string_list(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _text_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _truncate_evidence_text(value: Any, limit: int = 2_000) -> str | None:
    text = _text_or_none(value)
    if text is not None:
        text = sanitize_llm_text(text)
    if text is None or len(text) <= limit:
        return text

    urls = []
    seen_urls: set[str] = set()
    for match in re.findall(r"(?:https?|content)://[^\s<>\"']+", text, flags=re.IGNORECASE):
        url = match.rstrip(".,);]}")
        if url and url not in seen_urls:
            seen_urls.add(url)
            urls.append(url)
    url_block = "\nReferenced URIs: " + ", ".join(urls[:10]) if urls else ""
    url_block = url_block[: max(limit // 4, 100)]
    marker = f"\n... <{len(text) - limit} source chars omitted> ...\n"
    remaining = max(limit - len(marker) - len(url_block), 200)
    head_size = int(remaining * 0.7)
    tail_size = remaining - head_size
    return text[:head_size] + marker + url_block + text[-tail_size:]


def _compact_activity(value: Any, package: str | None) -> str | None:
    activity = _text_or_none(value)
    prefix = f"{package}/" if package else None
    if activity and prefix and activity.startswith(prefix):
        return activity[len(prefix):]
    return activity


def _compact_resource_id(value: Any, package: str | None) -> str | None:
    resource_id = _text_or_none(value)
    prefix = f"{package}:id/" if package else None
    if resource_id and prefix and resource_id.startswith(prefix):
        return resource_id[len(prefix):]
    return resource_id


def _is_structural_resource_only(
    class_name: str | None,
    resource_id: str | None,
) -> bool:
    if not class_name or not resource_id:
        return False
    class_suffix = class_name.rsplit(".", 1)[-1]
    if class_suffix not in {"View", "ViewGroup", "FrameLayout", "LinearLayout", "RelativeLayout"}:
        return False
    resource_suffix = resource_id.rsplit("/", 1)[-1].lower()
    return resource_suffix in {
        "action_bar",
        "action_bar_container",
        "container",
        "content",
        "decor_content_parent",
        "root",
    } or resource_suffix.endswith("background")


def _bounds_as_list(value: Any) -> list[int] | None:
    if value is None:
        return None
    if isinstance(value, str):
        numbers = re.findall(r"-?\d+", value)
        if len(numbers) >= 4:
            return [int(number) for number in numbers[:4]]
        return None
    if isinstance(value, (list, tuple)):
        flattened = []
        for item in value:
            if isinstance(item, (list, tuple)):
                flattened.extend(item)
            else:
                flattened.append(item)
        if len(flattened) >= 4:
            try:
                return [int(float(item)) for item in flattened[:4]]
            except (TypeError, ValueError):
                return None
    return None


def _image_binary_content(
    image_path: str | Path,
    max_edge: int = 1024,
    jpeg_quality: int = 85,
) -> BinaryContent:
    image_path = Path(image_path)
    if Image is not None:
        with Image.open(image_path) as image:
            image = image.convert("RGB")
            image.thumbnail((max_edge, max_edge))
            buffer = BytesIO()
            image.save(buffer, format="JPEG", quality=jpeg_quality, optimize=True)
        return BinaryContent(data=buffer.getvalue(), media_type="image/jpeg")

    media_type = mimetypes.guess_type(str(image_path))[0] or "image/png"
    return BinaryContent(data=image_path.read_bytes(), media_type=media_type)


def _summarize_screens(
    states: list[dict[str, Any]],
    start_index: int = 0,
) -> list[dict[str, Any]]:
    screens = []
    for index, state in enumerate(states, start=start_index):
        package = _text_or_none(state.get("package"))
        screens.append(
            {
                "screen_index": index,
                "captured_at": state.get("captured_at"),
                "package": package,
                "foreground_activity": _compact_activity(
                    state.get("foreground_activity"), package
                ),
            }
        )
    return screens


def _screen_summary_items(
    states: list[dict[str, Any]],
    start_index: int = 0,
) -> list[ScreenSummaryItem]:
    return [
        ScreenSummaryItem.model_validate(item)
        for item in _summarize_screens(states, start_index=start_index)
    ]


def _compact_state_for_xml_stage(state: dict[str, Any]) -> UIStateSnapshot:
    nodes: list[UIStateNode] = []
    seen: set[tuple[Any, ...]] = set()
    for node in state.get("ui_nodes", []):
        if not isinstance(node, dict):
            continue
        class_name = _text_or_none(node.get("class"))
        text = _truncate_evidence_text(node.get("text"))
        description = _truncate_evidence_text(node.get("content_description"))
        node_package = _text_or_none(node.get("package"))
        raw_resource_id = _text_or_none(node.get("resource_id"))
        resource_id = _compact_resource_id(raw_resource_id, node_package)
        bounds = _bounds_as_list(node.get("bounds"))
        actionable = any(node.get(key) for key in ("clickable", "scrollable", "editable"))
        special_class = bool(
            class_name
            and class_name.rsplit(".", 1)[-1]
            in {"WebView", "SurfaceView", "VideoView"}
        )
        external_package = bool(node_package and node_package != state.get("package"))
        structural_only = _is_structural_resource_only(class_name, raw_resource_id)
        if structural_only and not (
            text or description or actionable or special_class or external_package
        ):
            continue
        if not (text or description or resource_id or actionable or special_class or external_package):
            continue

        key = (class_name, resource_id, text, description, node_package, tuple(bounds or []))
        if key in seen:
            continue
        seen.add(key)
        nodes.append(
            UIStateNode(
                **{
                    "class": class_name,
                    "resource_id": resource_id,
                    "text": text,
                    "content_description": description,
                    "package": node_package if external_package else None,
                    "bounds": bounds,
                    "clickable": True if node.get("clickable") else None,
                    "scrollable": True if node.get("scrollable") else None,
                    "editable": True if node.get("editable") else None,
                }
            )
        )

    state_package = _text_or_none(state.get("package"))
    foreground_activity = _compact_activity(state.get("foreground_activity"), state_package)
    activity_stack = [
        compact_activity
        for activity in _string_list(state.get("activity_stack"))
        if (compact_activity := _compact_activity(activity, state_package))
    ]
    if activity_stack == [foreground_activity]:
        activity_stack = []
    fallback_values = _string_list(
        [
            *_string_list(state.get("extracted_text")),
            *_string_list(state.get("interactable_elements")),
        ]
    )
    text_fallback = (
        []
        if nodes
        else [
            compact_text
            for value in fallback_values
            if (compact_text := _truncate_evidence_text(value))
        ]
    )
    return UIStateSnapshot(
        state_type=state.get("state_type"),
        package=state_package,
        foreground_activity=foreground_activity,
        activity_stack=activity_stack,
        ui_hash=_text_or_none(state.get("ui_hash")),
        text_fallback=text_fallback,
        ui_nodes=nodes,
    )


def _event_relation(
    event: dict[str, Any],
    state_hash: str | None,
) -> Literal["incoming", "outgoing", "self"] | None:
    if not state_hash:
        return None
    starts_here = event.get("start_state_hash") == state_hash
    stops_here = event.get("stop_state_hash") == state_hash
    if starts_here and stops_here:
        return "self"
    if starts_here:
        return "outgoing"
    if stops_here:
        return "incoming"
    return None


def _event_action(event: dict[str, Any]) -> str | None:
    action = _text_or_none(
        event.get("action") or event.get("name") or event.get("event_name")
    )
    if action:
        return action
    event_str = _text_or_none(event.get("event_str"))
    if event_str:
        match = re.search(r"\bname=([^,)]+)", event_str)
        if match:
            return match.group(1).strip()
    return None

def _needs_raw_event(event: dict[str, Any]) -> bool:
    if not event.get("silent_payload_candidate"):
        return False

    if _event_action(event):
        return False

    has_semantic_target = any(
        _text_or_none(event.get(key))
        for key in (
            "view_text",
            "view_content_description",
            "view_resource_id",
            "action",
            "name",
            "event_name",
        )
    )
    return not has_semantic_target


def _extract_raw_event_hint(
    raw: RawEventRecord,
) -> str | None:
    payload = raw.raw_event_json
    if not isinstance(payload, dict):
        return None

    nested_event = payload.get("event")
    nested_event = nested_event if isinstance(nested_event, dict) else {}
    candidates = (
        payload.get("event_str"),
        payload.get("action"),
        payload.get("name"),
        payload.get("intent"),
        payload.get("data"),
        nested_event.get("action"),
        nested_event.get("name"),
        nested_event.get("event_type"),
    )

    for value in candidates:
        text = _text_or_none(value)
        if text:
            return sanitize_llm_text(text)

    return None

def _compact_ui_event(
    event: dict[str, Any],
    state_hash: str | None,
    deps: AndroidEvidenceDeps | None = None,
) -> UIEventRecord:
    action = _event_action(event)

    view_values = [
        _text_or_none(event.get(key))
        for key in (
            "view_text",
            "view_content_description",
            "view_resource_id",
            "view_class",
            "view_package",
        )
    ]

    event_str = _text_or_none(event.get("event_str"))
    if action or any(view_values) or _bounds_as_list(event.get("view_bounds")):
        event_str = None
    else:
        event_str = _truncate_evidence_text(event_str)

    record = UIEventRecord(
        event_id=_int_or_none(event.get("event_id")),
        timestamp=_float_or_none(event.get("timestamp")),
        event_type=_text_or_none(event.get("event_type")),
        relation_to_screen=_event_relation(event, state_hash),
        action=action,
        event_str=event_str,
        start_state_hash=_text_or_none(event.get("start_state_hash")),
        stop_state_hash=_text_or_none(event.get("stop_state_hash")),
        changed_state=event.get("changed_state"),
        unchanged_state=event.get("unchanged_state"),
        silent_payload_candidate=(
            True if event.get("silent_payload_candidate") else None
        ),
        view_text=_truncate_evidence_text(view_values[0]),
        view_content_description=_truncate_evidence_text(view_values[1]),
        view_resource_id=view_values[2],
        view_class=view_values[3],
        view_package=view_values[4],
        view_bounds=_bounds_as_list(event.get("view_bounds")),
    )

    if (
        deps is not None
        and record.event_id is not None
        and _needs_raw_event(event)
    ):
        raw = _internal_load_raw_event(deps, record.event_id)
        if raw:
            hint = _extract_raw_event_hint(raw)
            if hint:
                record.event_str = hint

    return record


def _trace_window_dict(value: Any) -> dict[str, float] | None:
    if not isinstance(value, dict):
        return None
    trace_window = {
        str(key): parsed
        for key, raw in value.items()
        if (parsed := _float_or_none(raw)) is not None
    }
    return trace_window or None


def _compact_native_trace(
    event: dict[str, Any],
    api_offset: int = 0,
    api_limit: int = 1000,
) -> NativeTraceRecord:
    summaries = event.get("native_behavior_summary")
    if summaries is None:
        summaries = []
    elif isinstance(summaries, (str, dict)):
        summaries = [summaries]
    elif isinstance(summaries, tuple):
        summaries = list(summaries)
    elif not isinstance(summaries, list):
        summaries = []

    trace_status = _text_or_none(event.get("trace_file_status")) or "UNKNOWN"
    trace_is_valid = trace_status.upper() == "VALID"
    total = len(summaries) if trace_is_valid else 0
    page_source = summaries if trace_is_valid else summaries[:1]
    effective_offset = api_offset if trace_is_valid else 0
    end_offset = min(effective_offset + api_limit, len(page_source))

    return NativeTraceRecord(
        event_id=_int_or_none(event.get("event_id")),
        trace_window=_trace_window_dict(event.get("trace_window")),
        trace_status=trace_status,
        api_calls_total=total,
        api_offset=effective_offset,
        native_behavior_summary=sanitize_llm_payload(
            page_source[effective_offset:end_offset]
        ),
        next_api_offset=end_offset if trace_is_valid and end_offset < total else None,
    )


def _event_summary(event: dict[str, Any]) -> EventSummaryItem:
    event_id = _int_or_none(event.get("event_id"))
    trace_status = _text_or_none(event.get("trace_file_status")) or "UNKNOWN"
    summaries = event.get("native_behavior_summary")
    api_calls_total = (
        len(summaries)
        if trace_status.upper() == "VALID" and isinstance(summaries, list)
        else int(trace_status.upper() == "VALID" and bool(summaries))
    )
    return EventSummaryItem(
        event_id=event_id,
        timestamp=_float_or_none(event.get("timestamp")),
        event_type=_text_or_none(event.get("event_type")),
        action=_event_action(event),
        start_state_hash=_text_or_none(event.get("start_state_hash")),
        stop_state_hash=_text_or_none(event.get("stop_state_hash")),
        trace_status=trace_status,
        api_calls_total=api_calls_total,
    )


def _ui_event_summary(event: dict[str, Any]) -> UIEventSummaryItem:
    """Build an event summary without trace status or API-call counts."""

    return UIEventSummaryItem(
        event_id=_int_or_none(event.get("event_id")),
        timestamp=_float_or_none(event.get("timestamp")),
        event_type=_text_or_none(event.get("event_type")),
        action=_event_action(event),
        start_state_hash=_text_or_none(event.get("start_state_hash")),
        stop_state_hash=_text_or_none(event.get("stop_state_hash")),
    )


MAX_RAW_EVENT_CHARS = 20_000
MAX_RAW_STRING_CHARS = 2_000
MAX_RAW_COLLECTION_ITEMS = 50


def _truncate_raw_value(value: Any, depth: int = 0) -> Any:
    if depth >= 6:
        return "<maximum nesting depth reached>"
    if isinstance(value, str):
        return _truncate_evidence_text(value, MAX_RAW_STRING_CHARS)
    if isinstance(value, dict):
        items = list(value.items())
        compact = {
            str(key): _truncate_raw_value(item, depth + 1)
            for key, item in items[:MAX_RAW_COLLECTION_ITEMS]
        }
        if len(items) > MAX_RAW_COLLECTION_ITEMS:
            compact["_omitted_fields"] = len(items) - MAX_RAW_COLLECTION_ITEMS
        return compact
    if isinstance(value, (list, tuple)):
        compact = [
            _truncate_raw_value(item, depth + 1)
            for item in value[:MAX_RAW_COLLECTION_ITEMS]
        ]
        if len(value) > MAX_RAW_COLLECTION_ITEMS:
            compact.append(f"<{len(value) - MAX_RAW_COLLECTION_ITEMS} items omitted>")
        return compact
    return value


def _bounded_raw_event_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], int, bool]:
    sanitized = _sanitize_llm_payload(payload)
    serialized = json.dumps(sanitized, ensure_ascii=False)
    original_size = len(serialized)
    if original_size <= MAX_RAW_EVENT_CHARS:
        return sanitized, original_size, False

    compact = _truncate_raw_value(sanitized)
    compact_text = json.dumps(compact, ensure_ascii=False)
    if len(compact_text) > MAX_RAW_EVENT_CHARS:
        compact = {
            "json_excerpt": compact_text[:MAX_RAW_EVENT_CHARS],
            "note": f"Raw event was truncated from {original_size} characters.",
        }
    return compact, original_size, True

def _events_for_state(
    deps: AndroidEvidenceDeps,
    state: dict[str, Any],
) -> list[dict[str, Any]]:
    state_hash = state.get("ui_hash")
    if not state_hash:
        return []
    events = []
    for event in sorted(deps.report.get("causal_events", []), key=_sort_key):
        if event.get("start_state_hash") == state_hash or event.get("stop_state_hash") == state_hash:
            events.append(event)
    return events


def _events_by_id_or_screen(
    deps: AndroidEvidenceDeps,
    event_id: int | None = None,
    screen_index: int | None = None,
) -> list[dict[str, Any]]:
    if event_id is not None:
        normalized_event_id = _int_or_none(event_id)
        return [
            event
            for event in sorted(deps.report.get("causal_events", []), key=_sort_key)
            if _int_or_none(event.get("event_id")) == normalized_event_id
        ]
    state = _state_at(deps, screen_index)
    if state is None:
        return []
    return _events_for_state(deps, state)


# ================= Tool Definitions =================
MAX_SCREEN_PAGE_SIZE = 50
MAX_EVENT_PAGE_SIZE = 25
MAX_API_EVENT_PAGE_SIZE = 5
MAX_API_PAGE_SIZE = 1000


@react_logger
async def list_screens(
    ctx: RunContext[AndroidEvidenceDeps],
    start_index: int = 0,
    limit: int = MAX_SCREEN_PAGE_SIZE,
) -> ScreenListResult:
    """List screen timeline metadata, returning at most 50 screens per call."""

    deps = ctx.deps
    if start_index < 0 or start_index > len(deps.states) or limit < 1:
        return _error_result(
            deps,
            ScreenListResult,
            "start_index is out of range or limit is less than 1.",
            screens_total=len(deps.states),
        )

    page_size = min(limit, MAX_SCREEN_PAGE_SIZE)
    end_index = min(start_index + page_size, len(deps.states))
    return ScreenListResult(
        observation_id=_next_observation_id(deps),
        ok=True,
        summary=f"Loaded screens {start_index} through {max(start_index, end_index - 1)}.",
        screens_total=len(deps.states),
        screens=_screen_summary_items(
            deps.states[start_index:end_index], start_index=start_index
        ),
        next_start_index=end_index if end_index < len(deps.states) else None,
    )


@react_logger
async def list_events(
    ctx: RunContext[AndroidEvidenceDeps],
    event_offset: int = 0,
    limit: int = MAX_SCREEN_PAGE_SIZE,
) -> EventListResult:
    """List every causal event, including events not associated with a screen."""

    deps = ctx.deps
    events_all = sorted(deps.report.get("causal_events", []), key=_sort_key)
    if event_offset < 0 or event_offset > len(events_all) or limit < 1:
        return _error_result(
            deps,
            EventListResult,
            "event_offset is out of range or limit is less than 1.",
            events_total=len(events_all),
        )

    page_size = min(limit, MAX_SCREEN_PAGE_SIZE)
    end_offset = min(event_offset + page_size, len(events_all))
    summaries = [_event_summary(event) for event in events_all[event_offset:end_offset]]
    return EventListResult(
        observation_id=_next_observation_id(deps),
        ok=True,
        summary=f"Loaded events {event_offset} through {max(event_offset, end_offset - 1)}.",
        events_total=len(events_all),
        events=summaries,
        next_event_offset=end_offset if end_offset < len(events_all) else None,
    )


@react_logger
async def list_ui_events(
    ctx: RunContext[AndroidEvidenceDeps],
    event_offset: int = 0,
    limit: int = MAX_SCREEN_PAGE_SIZE,
) -> UIEventListResult:
    """List causal event metadata without exposing API counts or trace status."""

    deps = ctx.deps
    events_all = sorted(deps.report.get("causal_events", []), key=_sort_key)
    if event_offset < 0 or event_offset > len(events_all) or limit < 1:
        return _error_result(
            deps,
            UIEventListResult,
            "event_offset is out of range or limit is less than 1.",
            events_total=len(events_all),
        )

    page_size = min(limit, MAX_SCREEN_PAGE_SIZE)
    end_offset = min(event_offset + page_size, len(events_all))
    summaries = [
        _ui_event_summary(event) for event in events_all[event_offset:end_offset]
    ]
    return UIEventListResult(
        observation_id=_next_observation_id(deps),
        ok=True,
        summary=(
            f"Loaded UI events {event_offset} through "
            f"{max(event_offset, end_offset - 1)}."
        ),
        events_total=len(events_all),
        events=summaries,
        next_event_offset=end_offset if end_offset < len(events_all) else None,
    )


@react_logger
async def inspect_screen(
    ctx: RunContext[AndroidEvidenceDeps],
    screen_index: int,
) -> InspectScreenResult | ToolReturn:
    """Attach one DroidBot screenshot with minimal identifying metadata."""

    deps = ctx.deps
    state = _state_at(deps, screen_index)
    if state is None:
        return _error_result(
            deps,
            InspectScreenResult,
            f"screen_index out of range: {screen_index}",
            screen_index=screen_index,
        )

    screenshot = _resolve_droidbot_file(deps, state.get("screenshot_file"))
    if screenshot and not screenshot.exists():
        screenshot = Path(state.get("screenshot_file"))

    image_path = str(screenshot) if screenshot and screenshot.exists() else None
    image_ref = _public_file_ref(screenshot) if screenshot else None

    binary_content = None
    if image_path:
        try:
            binary_content = _image_binary_content(image_path)
        except (OSError, ValueError) as exc:
            return _error_result(
                deps,
                InspectScreenResult,
                safe_exception_text(exc, "Screenshot could not be decoded"),
                screen_index=screen_index,
                captured_at=state.get("captured_at"),
                image_ref=image_ref,
            )

    deps.visited_screens.add(screen_index)

    observation = _result(
        deps=deps,
        result_cls=InspectScreenResult,
        ok=bool(image_path),
        summary=f"Attached screen {screen_index} captured at {state.get('captured_at')}.",
        error=None if image_path else "Screenshot file not found.",
        screen_index=screen_index,
        captured_at=state.get("captured_at"),
        package=state.get("package"),
        foreground_activity=_compact_activity(
            state.get("foreground_activity"), state.get("package")
        ),
        image_ref=image_ref,
    )
    if not image_path:
        return observation

    return ToolReturn(
        return_value=observation,
        content=[
            f"Screen {screen_index}.",
            binary_content,
        ],
        metadata={
            "tool": "INSPECT_SCREEN",
            "screen_index": screen_index,
            "image_ref": image_ref,
        },
    )


@react_logger
async def read_ui_state(
    ctx: RunContext[AndroidEvidenceDeps],
    screen_index: int,
) -> UIStateResult:
    """Read synchronized UI/XML semantic state for one screen."""

    deps = ctx.deps
    state = _state_at(deps, screen_index)
    if state is None:
        return _error_result(
            deps,
            UIStateResult,
            f"screen_index out of range: {screen_index}",
            screen_index=screen_index,
        )
    return _result(
        deps=deps,
        result_cls=UIStateResult,
        ok=True,
        summary=f"Loaded UI/XML semantic state for screen {screen_index}.",
        screen_index=screen_index,
        state_ref=_public_file_ref(state.get("raw_state_file") or state.get("state_file")),
        ui_state=_compact_state_for_xml_stage(state),
    )


@react_logger
async def read_related_events(
    ctx: RunContext[AndroidEvidenceDeps],
    screen_index: int,
    event_offset: int = 0,
    limit: int = MAX_EVENT_PAGE_SIZE,
) -> RelatedEventsResult:
    """Read related causal events, returning at most 25 events per call."""

    deps = ctx.deps
    state = _state_at(deps, screen_index)
    if state is None:
        return _error_result(
            deps,
            RelatedEventsResult,
            f"screen_index out of range: {screen_index}",
            screen_index=screen_index,
        )
    if event_offset < 0 or limit < 1:
        return _error_result(
            deps,
            RelatedEventsResult,
            "event_offset must be >= 0 and limit must be >= 1.",
            screen_index=screen_index,
        )

    related_all = _events_for_state(deps, state)
    if event_offset > len(related_all):
        return _error_result(
            deps,
            RelatedEventsResult,
            f"event_offset exceeds events_total={len(related_all)}.",
            screen_index=screen_index,
            events_total=len(related_all),
        )
    page_size = min(limit, MAX_EVENT_PAGE_SIZE)
    end_offset = min(event_offset + page_size, len(related_all))
    related = related_all[event_offset:end_offset]
    return _result(
        deps=deps,
        result_cls=RelatedEventsResult,
        ok=True,
        summary=(
            f"Loaded {len(related)} of {len(related_all)} related events "
            f"for screen {screen_index}."
        ),
        screen_index=screen_index,
        events_total=len(related_all),
        events=[_compact_ui_event(event, state.get("ui_hash"), deps) for event in related],
        next_event_offset=end_offset if end_offset < len(related_all) else None,
    )


@react_logger
async def read_api_calls(
    ctx: RunContext[AndroidEvidenceDeps],
    event_id: int | None = None,
    screen_index: int | None = None,
    event_offset: int = 0,
    limit: int = MAX_API_EVENT_PAGE_SIZE,
    api_offset: int = 0,
    api_limit: int = MAX_API_PAGE_SIZE,
) -> APICallsResult:
    """Read paged API evidence for one event or a small page of screen events."""

    deps = ctx.deps
    if event_offset < 0 or limit < 1 or api_offset < 0 or api_limit < 1:
        return _error_result(
            deps,
            APICallsResult,
            "event_offset/api_offset must be >= 0 and limit/api_limit must be >= 1.",
            evidence_status="invalid",
        )

    events_all = _events_by_id_or_screen(
        deps, event_id=event_id, screen_index=screen_index
    )
    if not events_all:
        return _error_result(
            deps,
            APICallsResult,
            "No matching event_id or screen-related events.",
            evidence_status="invalid",
        )
    if event_id is None and event_offset > len(events_all):
        return _error_result(
            deps,
            APICallsResult,
            f"event_offset exceeds events_total={len(events_all)}.",
            evidence_status="invalid",
            events_total=len(events_all),
        )

    if event_id is not None:
        events = events_all
        end_offset = len(events_all)
        summaries = events[0].get("native_behavior_summary") or []
        trace_is_valid = str(events[0].get("trace_file_status") or "UNKNOWN").upper() == "VALID"
        summaries_total = (
            len(summaries)
            if trace_is_valid and isinstance(summaries, list)
            else int(trace_is_valid and bool(summaries))
        )
        if api_offset > summaries_total:
            return _error_result(
                deps,
                APICallsResult,
                f"api_offset exceeds api_calls_total={summaries_total} for event_id={event_id}.",
                evidence_status="invalid",
                events_total=1,
            )
    else:
        page_size = min(limit, MAX_API_EVENT_PAGE_SIZE)
        end_offset = min(event_offset + page_size, len(events_all))
        events = events_all[event_offset:end_offset]

    event_ids: list[int] = []
    trace_statuses: dict[str, list[int]] = {}
    payload: list[NativeTraceRecord] = []
    for event in events:
        parsed_event_id = _int_or_none(event.get("event_id"))
        trace_status = _text_or_none(event.get("trace_file_status")) or "UNKNOWN"
        if parsed_event_id is not None:
            event_ids.append(parsed_event_id)
            trace_statuses.setdefault(trace_status, []).append(parsed_event_id)
        payload.append(
            _compact_native_trace(
                event,
                api_offset=api_offset,
                api_limit=min(api_limit, MAX_API_PAGE_SIZE),
            )
        )

    has_api_evidence = any(
        (trace.trace_status or "").upper() == "VALID"
        and trace.api_calls_total > 0
        for trace in payload
    )
    all_traces_valid = bool(trace_statuses) and all(
        status.upper() == "VALID" for status in trace_statuses
    )
    if has_api_evidence and all_traces_valid:
        evidence_status = "available"
    elif has_api_evidence:
        evidence_status = "partial"
    elif all_traces_valid:
        evidence_status = "empty"
    else:
        evidence_status = "unavailable"

    return _result(
        deps=deps,
        result_cls=APICallsResult,
        ok=True,
        summary=f"Checked API evidence for {len(events)} event(s).",
        evidence_status=evidence_status,
        events_total=len(events_all),
        event_ids=event_ids,
        trace_statuses=trace_statuses,
        api_calls=payload,
        next_event_offset=(
            end_offset
            if event_id is None and end_offset < len(events_all)
            else None
        ),
    )


def _internal_load_raw_event(
    deps: AndroidEvidenceDeps,
    event_id: int,
) -> RawEventRecord | None:
    events = _events_by_id_or_screen(deps, event_id=event_id)
    if not events:
        return None
    event = events[0]
    event_file = _resolve_droidbot_file(deps, event.get("event_file"))
    if not event_file or not event_file.exists():
        return None
    try:
        loaded = _json_load(event_file)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(loaded, dict):
        loaded = {"raw_value": loaded}
    raw_json, original_size, truncated = _bounded_raw_event_payload(loaded)
    return RawEventRecord(
        event_id=_int_or_none(event.get("event_id")),
        raw_event_json=raw_json,
        original_size_chars=original_size,
        truncated=truncated,
    )


@react_logger
async def read_raw_event(
    ctx: RunContext[AndroidEvidenceDeps],
    event_id: int | None = None,
    screen_index: int | None = None,
) -> RawEventResult:
    """Read one raw DroidBot event when compact event evidence is insufficient."""

    deps = ctx.deps
    events = _events_by_id_or_screen(deps, event_id=event_id, screen_index=screen_index)
    if not events:
        return _error_result(
            deps,
            RawEventResult,
            "No matching event_id or screen-related events.",
        )

    first_event_id = _int_or_none(events[0].get("event_id"))
    raw_event = (
        _internal_load_raw_event(deps, first_event_id)
        if first_event_id is not None
        else None
    )
    if raw_event is None:
        return _error_result(
            deps,
            RawEventResult,
            "The matching event has no readable raw event file.",
            events_total=len(events),
            truncated=len(events) > 1,
        )

    return _result(
        deps=deps,
        result_cls=RawEventResult,
        ok=True,
        summary="Loaded one raw event; request another event by event_id if needed.",
        events_total=len(events),
        raw_events=[raw_event],
        truncated=len(events) > 1 or raw_event.truncated,
    )


_UI_EVENT_HIDDEN_API_KEYS = {
    "api_calls",
    "api_calls_total",
    "api_limit",
    "api_offset",
    "api_signature",
    "native_behavior_summary",
    "next_api_offset",
    "sensitive_api_hits",
    "total_sensitive_api_hits",
    "trace_file",
    "trace_file_status",
    "trace_status",
    "trace_window",
}


def _strip_api_trace_fields(value: Any) -> Any:
    """Recursively remove API/trace metadata from UI/Event raw evidence."""

    if isinstance(value, dict):
        return {
            str(key): _strip_api_trace_fields(item)
            for key, item in value.items()
            if str(key).lower() not in _UI_EVENT_HIDDEN_API_KEYS
        }
    if isinstance(value, list):
        return [_strip_api_trace_fields(item) for item in value]
    return value


@react_logger
async def read_raw_ui_event(
    ctx: RunContext[AndroidEvidenceDeps],
    event_id: int | None = None,
    screen_index: int | None = None,
) -> RawEventResult:
    """Read one raw UI event while excluding all API and trace metadata."""

    deps = ctx.deps
    events = _events_by_id_or_screen(deps, event_id=event_id, screen_index=screen_index)
    if not events:
        return _error_result(
            deps,
            RawEventResult,
            "No matching event_id or screen-related events.",
        )

    first_event_id = _int_or_none(events[0].get("event_id"))
    raw_event = (
        _internal_load_raw_event(deps, first_event_id)
        if first_event_id is not None
        else None
    )
    if raw_event is None:
        return _error_result(
            deps,
            RawEventResult,
            "The matching event has no readable raw event file.",
            events_total=len(events),
            truncated=len(events) > 1,
        )

    ui_safe_raw_event = raw_event.model_copy(
        update={"raw_event_json": _strip_api_trace_fields(raw_event.raw_event_json)}
    )
    return _result(
        deps=deps,
        result_cls=RawEventResult,
        ok=True,
        summary=(
            "Loaded one raw UI event without API/trace metadata; "
            "request another event by event_id if needed."
        ),
        events_total=len(events),
        raw_events=[ui_safe_raw_event],
        truncated=len(events) > 1 or ui_safe_raw_event.truncated,
    )


@react_logger
async def next_screen(
    ctx: RunContext[AndroidEvidenceDeps],
    screen_index: int,
) -> NextScreenResult:
    """Return the next screen summary without inspecting its image."""

    deps = ctx.deps
    if screen_index < -1 or screen_index >= len(deps.states):
        return _error_result(
            deps,
            NextScreenResult,
            f"screen_index out of range: {screen_index}",
            done=True,
        )

    next_index = screen_index + 1
    if next_index >= len(deps.states):
        return _result(
            deps=deps,
            result_cls=NextScreenResult,
            ok=True,
            summary="No more screens are available.",
            done=True,
        )

    state = deps.states[next_index]
    package = _text_or_none(state.get("package"))
    return _result(
        deps=deps,
        result_cls=NextScreenResult,
        ok=True,
        summary=f"Next screen index is {next_index}.",
        next_screen_index=next_index,
        done=False,
        captured_at=_text_or_none(state.get("captured_at")),
        package=package,
        foreground_activity=_compact_activity(
            state.get("foreground_activity"), package
        ),
    )


@react_logger
async def first_related_event(
    ctx: RunContext[AndroidEvidenceDeps],
    screen_index: int,
) -> FirstRelatedEventResult:
    """Return the first related event id without loading event details."""

    deps = ctx.deps
    state = _state_at(deps, screen_index)
    if state is None:
        return _error_result(
            deps,
            FirstRelatedEventResult,
            f"screen_index out of range: {screen_index}",
            screen_index=screen_index,
            has_related_event=False,
        )

    events = _events_for_state(deps, state)
    event_id = _int_or_none(events[0].get("event_id")) if events else None
    return _result(
        deps=deps,
        result_cls=FirstRelatedEventResult,
        ok=True,
        summary=(
            f"First related event for screen {screen_index} is {event_id}."
            if event_id is not None
            else f"No related event found for screen {screen_index}."
        ),
        screen_index=screen_index,
        has_related_event=event_id is not None,
        event_id=event_id,
    )


__all__ = [
    "AndroidEvidenceDeps",
    "AndroidEvidencePathConfig",
    "APICallsResult",
    "EventListResult",
    "EventSummaryItem",
    "FirstRelatedEventResult",
    "InspectScreenResult",
    "NativeTraceRecord",
    "NextScreenResult",
    "RawEventRecord",
    "RawEventResult",
    "RelatedEventsResult",
    "ScreenListResult",
    "ScreenSummaryItem",
    "ToolBaseResult",
    "UIEventListResult",
    "UIEventRecord",
    "UIEventSummaryItem",
    "UIStateNode",
    "UIStateResult",
    "UIStateSnapshot",
    "detect_evidence_path_config",
    "first_related_event",
    "inspect_screen",
    "llm_safe_file_ref",
    "llm_safe_report_ref",
    "list_events",
    "list_ui_events",
    "list_screens",
    "next_screen",
    "read_api_calls",
    "read_raw_event",
    "read_raw_ui_event",
    "read_related_events",
    "read_ui_state",
    "react_logger",
    "resolve_droidbot_output_dir",
    "safe_exception_text",
    "sanitize_llm_payload",
    "sanitize_llm_text",
]
