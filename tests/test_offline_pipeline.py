"""Exercise the refactored pipeline without external providers or Android."""
import asyncio
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path

from pydantic_ai.models.test import TestModel

from moirae.config import RunnerConfig
from moirae.evidence.tools import AndroidEvidenceDeps, sanitize_llm_text
from moirae.preprocessing.trace_reducer import TraceSemanticReducer
from moirae.reasoning import pipeline
from moirae.reasoning.reporting import rebuild_existing_outputs
from moirae.reasoning.runtime import isolated_agent_deps


class OfflinePipelineTests(unittest.IsolatedAsyncioTestCase):
    def models(self):
        stack = ExitStack()
        for agent in (pipeline.vision_agent, pipeline.ui_event_agent, pipeline.api_agent):
            stack.enter_context(agent.override(model=TestModel(call_tools=[])))
        stack.enter_context(pipeline.judge_agent.override(model=TestModel(
            call_tools=[], custom_output_args={
                "apk_name": "model-name-is-normalized",
                "is_malicious": False,
                "threat_category(Malicious family)": "Benign",
                "confidence_score": 50,
                "reason": "Synthetic offline test only.",
                "evidence_chain": ["1. Synthetic evidence."],
            },
        )))
        return stack

    async def test_pipeline_writes_resumes_and_rebuilds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "sample.json"
            report.write_text(json.dumps({
                "target_package": "org.example.offline",
                "semantic_timeline": [], "causal_events": [],
                "trace_processing": {"final_trace_status": "EMPTY_FILE"},
            }), encoding="utf-8")
            output = root / "results"
            with self.models():
                await pipeline.run_batch_task(report, output, RunnerConfig(agent_retries=1))
            public_path = output / "multi_agent_analysis_reports.json"
            public = json.loads(public_path.read_text(encoding="utf-8"))
            self.assertEqual(len(public), 1)
            self.assertEqual(public[0]["status"], "success")
            self.assertEqual(public[0]["apk_name"], "sample")
            self.assertFalse(public[0]["is_malicious"])
            audit_path = next((output / "multi_agent_audits").glob("*.json"))
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            self.assertEqual(len(audit["analysis"]["stage_audits"]), 3)
            self.assertEqual(audit["analysis"]["judge_audit"]["status"], "success")
            self.assertIsNotNone(audit["analysis"]["judge_audit"]["token_usage"]["total_tokens"])
            original_audit = audit_path.read_bytes()
            # A successful sample must resume without invoking a provider.
            with self.models():
                await pipeline.run_batch_task(report, output, RunnerConfig(agent_retries=1))
            self.assertEqual(audit_path.read_bytes(), original_audit)
            rebuild_existing_outputs(output)
            rebuilt = json.loads(public_path.read_text(encoding="utf-8"))
            self.assertEqual(rebuilt[0]["status"], "success")
            self.assertTrue((output / "timing_stats.json").is_file())
            self.assertTrue((output / "llm_multi_agent_trace_full.md").is_file())

    async def test_bookkeeping_isolation(self):
        deps = AndroidEvidenceDeps(sample_hash="sample", report_path="sample.json", report={}, states=[])
        first = isolated_agent_deps(deps)
        second = isolated_agent_deps(deps)
        first.visited_screens.add(1)
        self.assertEqual(second.visited_screens, set())
        self.assertEqual(deps.visited_screens, set())


class EvidenceTests(unittest.TestCase):
    def test_namespace_boundary(self):
        reducer = TraceSemanticReducer(Path("sample.trace"), Path("sample.json"), Path("output"), [])
        self.assertTrue(reducer._matches_namespace("java.lang.String.valueOf", "java.lang"))
        self.assertFalse(reducer._matches_namespace("java.language.Other", "java.lang"))

    def test_missing_trace_remains_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            semantic = root / "semantic.json"
            semantic.write_text(json.dumps({"causal_events": [{"event_id": 1, "timestamp": 0}]}), encoding="utf-8")
            reducer = TraceSemanticReducer(root / "missing.trace", semantic, root / "out", [])
            result = reducer.process()
            self.assertEqual(result["status"], "MISSING_FILE")
            report = json.loads(result["output_path"].read_text(encoding="utf-8"))
            self.assertEqual(report["trace_processing"]["final_trace_status"], "MISSING_FILE")
            self.assertEqual(report["causal_events"][0]["native_behavior_call_order"], [])

    def test_private_path_is_sanitized(self):
        text = sanitize_llm_text("Evidence: /private/dataset/malware/sample.json")
        self.assertNotIn("/private/dataset/malware", text)


if __name__ == "__main__":
    unittest.main()
