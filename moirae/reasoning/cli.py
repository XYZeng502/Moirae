"""Cli components extracted from the original Moirae runner."""
import argparse
import asyncio
import sys
from pathlib import Path
from ..config import AGENT_REPORT_DIR, API_KEY, OUTPUT_SCHEMA_VERSION, REASONING_OUTPUT_DIR, RunnerConfig
from .pipeline import run_batch_task
from .reporting import rebuild_existing_outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PydanticAI multi-agent Android malware reasoning over dynamic evidence."
    )
    parser.add_argument("--agent-report", type=Path, default=AGENT_REPORT_DIR, help="A fused JSON report or directory produced by moirae-reduce.")
    parser.add_argument("--output-dir", type=Path, default=REASONING_OUTPUT_DIR, help="Directory for multi-agent reasoning outputs.")
    parser.add_argument(
        "--agent-retries",
        type=int,
        default=5,
        help=(
            "Maximum top-level agent.run attempts per logical Agent stage, including the "
            "initial attempt (legacy option name retained for compatibility)."
        ),
    )
    parser.add_argument("--retry-initial-wait", type=int, default=20, help="Initial retry wait seconds for rate-limit backoff.")
    parser.add_argument(
        "--rebuild-output-only",
        action="store_true",
        help=(
            f"Migrate existing audit files and rebuild all schema-{OUTPUT_SCHEMA_VERSION} JSON/Markdown outputs "
            "without calling any LLM."
        ),
    )
    return parser


async def main_async() -> None:
    args = build_parser().parse_args()
    if args.rebuild_output_only:
        rebuild_existing_outputs(args.output_dir)
        return
    if not API_KEY:
        raise SystemExit("Set MOIRAE_API_KEY (or legacy MiniMax_API_KEY) before LLM execution.")
    config = RunnerConfig(
        agent_retries=args.agent_retries,
        retry_initial_wait=args.retry_initial_wait,
    )
    await run_batch_task(args.agent_report, args.output_dir, config)


def main() -> None:
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main_async())


if __name__ == "__main__":
    main()


