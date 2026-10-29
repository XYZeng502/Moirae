"""Align ART calls with semantic event windows and filter Java namespaces."""
import argparse
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


from ..config import DATASET_ROOT, PROJECT_ROOT

TRACE_INPUT_DIR = DATASET_ROOT / "traces" / "droidbot" / "benign"
XML_INPUT_DIR = DATASET_ROOT / "xml_states" / "droidbot" / "benign"
AGENT_OUTPUT_DIR = DATASET_ROOT / "agent_workspace" / "benign"
DEFAULT_NAMESPACE_FILE = Path(__file__).resolve().parents[1] / "resources" / "whitelist_packages_java.txt"



class TraceSemanticReducer:
    def __init__(self, trace_path: Path, semantic_json_path: Path, output_dir: Path, allowed_namespaces):
        self.trace_path = trace_path
        self.semantic_json_path = semantic_json_path
        self.output_dir = output_dir
        self.allowed_namespaces = allowed_namespaces
        self._match_cache = {}

    def _is_monitored_api(self, method_name: str) -> bool:
        if not self.allowed_namespaces:
            return True
        cached = self._match_cache.get(method_name)
        if cached is not None:
            return cached

        matched = any(self._matches_namespace(method_name, namespace) for namespace in self.allowed_namespaces)
        self._match_cache[method_name] = matched
        return matched

    def _matches_namespace(self, method_name: str, namespace: str) -> bool:
        namespace = namespace.strip().removesuffix(".*")
        if not namespace:
            return False
        return (
            method_name == namespace
            or method_name.startswith(f"{namespace}.")
            or method_name.startswith(f"{namespace}$")
        )

    def process(self):
        with self.semantic_json_path.open("r", encoding="utf-8") as f:
            semantic_data = json.load(f)

        causal_events = semantic_data.get("causal_events", [])
        if not causal_events:
            return {
                "status": "NO_EVENTS",
                "output_path": None,
                "event_count": 0,
                "hit_count": 0,
            }

        time_windows = []
        for event in causal_events:
            trace_window = event.get("trace_window") or {}
            timestamp = event.get("timestamp")
            start = trace_window.get("start")
            end = trace_window.get("end")
            if start is None or end is None:
                if timestamp is None:
                    continue
                start = max(0.0, float(timestamp) - 0.5)
                end = float(timestamp) + 2.5

            time_windows.append(
                {
                    "event_id": event.get("event_id", "unknown"),
                    "start": float(start),
                    "end": float(end),
                    "api_counter": defaultdict(int),
                    "api_order": [],
                }
            )

        if not time_windows:
            return {
                "status": "NO_TRACE_WINDOWS",
                "output_path": None,
                "event_count": len(causal_events),
                "hit_count": 0,
            }

        trace_status = self._trace_status()
        total_hits = 0

        if trace_status == "VALID":
            total_hits, trace_status = self._scan_trace(time_windows)

        enriched_events = []
        windows_by_event_id = {window["event_id"]: window for window in time_windows}
        for original_event in causal_events:
            event = dict(original_event)
            event["trace_file_status"] = trace_status
            window = windows_by_event_id.get(event.get("event_id"))

            if trace_status != "VALID":
                event["native_behavior_summary"] = [self._trace_status_message(trace_status)]
                event["native_behavior_call_order"] = []
                event["native_behavior_has_risks"] = False
            elif window is None:
                event["native_behavior_summary"] = []
                event["native_behavior_call_order"] = []
                event["native_behavior_has_risks"] = False
            else:
                event["native_behavior_summary"] = [
                    f"{api} (Call {count} times)"
                    for api, count in self._ordered_api_counts(window)
                ]
                event["native_behavior_call_order"] = [
                    {"api": api, "count": count}
                    for api, count in self._ordered_api_counts(window)
                ]
                event["native_behavior_has_risks"] = bool(event["native_behavior_summary"])
            enriched_events.append(event)

        semantic_data["causal_events"] = enriched_events
        semantic_data["trace_processing"] = {
            "processed_trace": self.trace_path.name,
            "final_trace_status": trace_status,
            "total_sensitive_api_hits": total_hits if trace_status == "VALID" else 0,
            "total_events": len(causal_events),
            "total_windows": len(time_windows),
            "namespace_filter_count": len(self.allowed_namespaces),
            "namespace_filter_mode": "package_boundary_prefix",
            "native_behavior_order": "first_observed_call_order",
            "trace_file_empty": trace_status == "EMPTY_FILE",
            "trace_status_message": self._trace_status_message(trace_status),
        }

        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.output_dir / f"{self.trace_path.stem}.json"
        output_path.write_text(json.dumps(semantic_data, indent=4, ensure_ascii=False), encoding="utf-8")

        return {
            "status": trace_status,
            "output_path": output_path,
            "event_count": len(causal_events),
            "hit_count": total_hits if trace_status == "VALID" else 0,
        }

    def _trace_status(self):
        if not self.trace_path.exists():
            return "MISSING_FILE"
        if self.trace_path.stat().st_size == 0:
            return "EMPTY_FILE"
        return "VALID"

    def _trace_status_message(self, trace_status):
        messages = {
            "EMPTY_FILE": "[System_Fact] Trace file is empty; no ART method calls were recorded for this sample.",
            "MISSING_FILE": "[System_Fact] Trace file is missing; native behavior cannot be recovered for this sample.",
            "NO_VALID_RECORDS": "[System_Fact] Trace file exists, but no valid ART method-call records were parsed.",
            "NO_METHOD_TABLE": "[System_Fact] Trace file exists, but the ART method table is missing or unreadable.",
            "INVALID_BINARY_TRACE": "[System_Fact] Trace file exists, but the ART binary payload is invalid.",
            "UNSUPPORTED_TRACE_VERSION": "[System_Fact] Trace file exists, but its ART trace version or record size is unsupported.",
            "VALID": "[System_Fact] Trace file was parsed successfully.",
        }
        return messages.get(trace_status, f"[System_Fact] Trace processing status: {trace_status}.")

    def _record_api_hit(self, window, method_name):
        if window["api_counter"][method_name] == 0:
            window["api_order"].append(method_name)
        window["api_counter"][method_name] += 1

    def _ordered_api_counts(self, window):
        return [(api, window["api_counter"][api]) for api in window["api_order"]]

    def _scan_trace(self, time_windows):
        data = self.trace_path.read_bytes()
        marker = b"*end\n"
        marker_index = data.find(marker)
        if marker_index >= 0:
            return self._scan_art_binary_trace(data, marker_index + len(marker), time_windows)
        return self._scan_text_trace(time_windows)

    def _scan_text_trace(self, time_windows):
        base_usec = None
        total_hits = 0

        with self.trace_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip() or line.startswith("*") or line.startswith("VERSION"):
                    continue

                parts = line.split()
                if len(parts) < 4 or parts[1] != "ent":
                    continue

                try:
                    usecs = int(parts[2])
                except ValueError:
                    continue

                if base_usec is None:
                    base_usec = usecs
                relative_sec = (usecs - base_usec) / 1_000_000.0

                method_name = parts[3].lstrip(". ")
                if not self._is_monitored_api(method_name):
                    continue

                for window in time_windows:
                    if window["start"] <= relative_sec <= window["end"]:
                        self._record_api_hit(window, method_name)
                        total_hits += 1

        if base_usec is None:
            return 0, "NO_VALID_RECORDS"
        return total_hits, "VALID"

    def _scan_art_binary_trace(self, data, binary_start, time_windows):
        method_map = self._parse_method_table(data[:binary_start])
        if not method_map:
            return 0, "NO_METHOD_TABLE"

        if len(data) < binary_start + 18 or data[binary_start:binary_start + 4] != b"SLOW":
            return 0, "INVALID_BINARY_TRACE"

        version = struct.unpack_from("<H", data, binary_start + 4)[0]
        data_offset = struct.unpack_from("<H", data, binary_start + 6)[0]
        record_start = binary_start + data_offset
        record_size = self._record_size_for_version(data, binary_start, version)
        if record_size <= 0 or record_start >= len(data):
            return 0, "UNSUPPORTED_TRACE_VERSION"

        base_usec = None
        total_hits = 0

        for pos in range(record_start, len(data) - record_size + 1, record_size):
            parsed = self._parse_trace_record(data, pos, record_size)
            if parsed is None:
                continue

            method_action, usecs = parsed
            if base_usec is None:
                base_usec = usecs

            action = method_action & 0x3
            if action != 0:
                continue

            method_id = method_action & ~0x3
            method_name = method_map.get(method_id)
            if not method_name or not self._is_monitored_api(method_name):
                continue

            relative_sec = (usecs - base_usec) / 1_000_000.0
            for window in time_windows:
                if window["start"] <= relative_sec <= window["end"]:
                    self._record_api_hit(window, method_name)
                    total_hits += 1

        if base_usec is None:
            return 0, "NO_VALID_RECORDS"
        return total_hits, "VALID"

    def _parse_method_table(self, header_bytes):
        header_text = header_bytes.decode("utf-8", errors="ignore")
        method_map = {}
        for line in header_text.splitlines():
            if not line.startswith("0x"):
                continue

            parts = line.split("\t")
            if len(parts) < 3:
                continue

            try:
                method_id = int(parts[0], 16)
            except ValueError:
                continue

            class_name = parts[1].strip()
            method_name = parts[2].strip()
            if class_name and method_name:
                method_map[method_id] = f"{class_name}.{method_name}"
        return method_map

    def _record_size_for_version(self, data, binary_start, version):
        if version >= 3 and len(data) >= binary_start + 18:
            return struct.unpack_from("<H", data, binary_start + 16)[0]
        if version == 2:
            return 10
        if version == 1:
            return 9
        return 0

    def _parse_trace_record(self, data, pos, record_size):
        if record_size == 14:
            _, method_action, _, wall_time = struct.unpack_from("<HIII", data, pos)
            return method_action, wall_time
        if record_size == 10:
            _, method_action, wall_time = struct.unpack_from("<HII", data, pos)
            return method_action, wall_time
        if record_size == 9:
            _, method_action, wall_time = struct.unpack_from("<BII", data, pos)
            return method_action, wall_time
        return None


def load_namespaces(file_path: Path):
    if not file_path.exists():
        return set(), "MISSING_NAMESPACE_FILE"

    namespaces = set()
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            namespace = line.strip()
            if namespace and not namespace.startswith("#"):
                namespaces.add(namespace)
    return namespaces, "OK"


def collect_trace_files(trace_path: Path):
    if trace_path.is_file():
        return [trace_path] if trace_path.suffix == ".trace" else []
    if trace_path.is_dir():
        return sorted(trace_path.rglob("*.trace"))
    return []


def resolve_semantic_json(trace_file: Path, semantic_path: Path):
    if semantic_path.is_file():
        return semantic_path if semantic_path.name == "xml_semantic_stream.json" else None
    return semantic_path / trace_file.stem / "xml_semantic_stream.json"


def reduce_traces(trace_files, semantic_path, output_dir, allowed_namespaces):
    stats = Counter()
    outputs = []
    iterator = (
        tqdm(trace_files, desc="Reducing traces", unit="trace", dynamic_ncols=True, file=sys.stdout)
        if tqdm is not None
        else trace_files
    )

    for trace_file in iterator:
        semantic_json = resolve_semantic_json(trace_file, semantic_path)
        if semantic_json is None or not semantic_json.exists():
            stats["missing_semantic"] += 1
            continue

        try:
            result = TraceSemanticReducer(
                trace_path=trace_file,
                semantic_json_path=semantic_json,
                output_dir=output_dir,
                allowed_namespaces=allowed_namespaces,
            ).process()
        except (json.JSONDecodeError, OSError, UnicodeError):
            stats["failed"] += 1
            continue

        status = result["status"]
        stats["processed"] += 1
        stats[f"status_{status}"] += 1
        stats["events"] += result["event_count"]
        stats["sensitive_api_hits"] += result["hit_count"]
        if result["output_path"]:
            outputs.append(result["output_path"])

    return stats, outputs


def build_parser():
    parser = argparse.ArgumentParser(description="Fuse DroidBot semantic events with ART trace time windows.")
    parser.add_argument("--trace", type=Path, default=TRACE_INPUT_DIR, help="A .trace file or a directory containing .trace files.")
    parser.add_argument(
        "--semantic-json",
        type=Path,
        default=XML_INPUT_DIR,
        help="A xml_semantic_stream.json file or the semantic report root directory.",
    )
    parser.add_argument("--output-dir", type=Path, default=AGENT_OUTPUT_DIR, help="Directory for fused JSON reports.")
    parser.add_argument("--namespace-file", type=Path, default=DEFAULT_NAMESPACE_FILE, help="Java namespace whitelist file.")
    return parser


def main():
    args = build_parser().parse_args()
    allowed_namespaces, namespace_status = load_namespaces(args.namespace_file)
    trace_files = collect_trace_files(args.trace)

    stats, outputs = reduce_traces(
        trace_files=trace_files,
        semantic_path=args.semantic_json,
        output_dir=args.output_dir,
        allowed_namespaces=allowed_namespaces,
    )

    print("\nTrace reducer summary")
    print(f"  Trace input: {args.trace}")
    print(f"  Semantic input: {args.semantic_json}")
    print(f"  Output dir: {args.output_dir}")
    print(f"  Namespace file: {args.namespace_file} ({namespace_status}, {len(allowed_namespaces)} namespaces)")
    print(f"  Trace files found: {len(trace_files)}")
    print(f"  Reports written: {len(outputs)}")
    print(f"  Missing semantic reports: {stats['missing_semantic']}")
    print(f"  Failed samples: {stats['failed']}")
    print(f"  Events processed: {stats['events']}")
    print(f"  Sensitive API hits: {stats['sensitive_api_hits']}")
    for key in sorted(k for k in stats if k.startswith("status_")):
        print(f"  {key.removeprefix('status_')}: {stats[key]}")


if __name__ == "__main__":
    main()
