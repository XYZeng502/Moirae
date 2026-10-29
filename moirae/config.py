"""Portable paths and provider configuration; never store credentials in source."""
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_ROOT = Path(os.getenv("ANDROID_EVIDENCE_DATASET_ROOT", str(PROJECT_ROOT / "data")))
AGENT_REPORT_DIR = Path(os.getenv("MULTI_AGENT_REPORT_DIR", str(DATASET_ROOT / "agent_workspace" / "benign")))
REASONING_OUTPUT_DIR = Path(os.getenv("MULTI_AGENT_OUTPUT_DIR", str(PROJECT_ROOT / "outputs" / "reasoning")))

# Legacy provider environment names remain accepted for existing deployments.
API_KEY = os.getenv("MOIRAE_API_KEY") or os.getenv("MiniMax_API_KEY", "")
BASE_URL = os.getenv("MOIRAE_BASE_URL") or os.getenv("MiniMax_BASE_URL", "https://api.minimax.chat/v1")
VISION_MODEL_NAME = os.getenv("VISION_AGENT_MODEL", "MiniMax-M3")
TEXT_MODEL_NAME = os.getenv("TEXT_AGENT_MODEL", "MiniMax-M3")
JUDGE_MODEL_NAME = os.getenv("JUDGE_AGENT_MODEL", "MiniMax-M3")
STRUCTURED_OUTPUT_RETRIES = 3
AGENT_KEYS = {
    "Vision Agent": "vision_agent",
    "UI/Event Agent": "ui_event_agent",
    "API Agent": "api_agent",
    "Judge Agent": "judge_agent",
}
TOKEN_SUMMARY_START = "<!-- AGENT_TOKEN_SUMMARY_START -->"
TOKEN_SUMMARY_END = "<!-- AGENT_TOKEN_SUMMARY_END -->"

@dataclass
class RunnerConfig:
    """Limits for whole-stage retry attempts and rate-limit backoff."""
    agent_retries: int = 5
    retry_initial_wait: int = 20

OUTPUT_SCHEMA_VERSION = "3.0"
PIPELINE_EXECUTION_STRATEGY = "parallel_independent_react_then_single_judge"
LEGACY_ROUND_EXECUTION_STRATEGY = "parallel_evidence_then_serial_judge"
PARALLEL_EVIDENCE_AGENTS = ("vision_agent", "ui_event_agent", "api_agent")
PUBLIC_REPORT_FIELDS = (
    "apk_name", "is_malicious", "threat_category(Malicious family)",
    "confidence_score", "reason", "evidence_chain", "source_index", "status",
)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def execution_descriptor() -> dict:
    return {
        "sample_scheduling": "sequential",
        "pipeline_strategy": PIPELINE_EXECUTION_STRATEGY,
        "parallel_evidence_agents": list(PARALLEL_EVIDENCE_AGENTS),
        "logical_evidence_agent_runs_per_sample": 1,
        "logical_judge_runs_per_sample": 1,
        "logical_agent_runs_per_sample": 4,
        "synchronization_barrier": "judge_starts_after_all_parallel_evidence_agents_finish",
    }

def retry_policy_descriptor(config: RunnerConfig) -> dict:
    return {
        "top_level_max_attempts_per_agent_run": max(1, int(config.agent_retries)),
        "top_level_retryable_errors": ["429", "rate limit", "rejected"],
        "structured_output_retry_limit_per_agent_run": STRUCTURED_OUTPUT_RETRIES,
    }
