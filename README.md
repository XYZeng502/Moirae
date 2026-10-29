# Moirae

Moirae analyzes Android application behavior using three independent evidence
agents and one final Judge. Each evidence agent performs a whole-APK ReAct
investigation. Vision reviews screenshots, UI/Event reconstructs interface and
event causality, and API reviews ART method traces. The evidence agents run
concurrently; the Judge receives their final summaries after all three finish.

This repository contains the research implementation and the accompanying
[manuscript](docs/Moirae.pdf). APK datasets, generated evidence, model outputs,
credentials, the Android SDK, and DroidBot are not bundled.

## Repository layout

```text
moirae/
  config.py                  Environment configuration and execution metadata
  collection/
    runner.py                APK lifecycle, emulator recovery, and recording
    action_runner.py         DroidBot actions-only subprocess
    state_parser.py          DroidBot states/events to semantic JSON
  preprocessing/
    trace_reducer.py          ART trace filtering and event-window alignment
  evidence/
    tools.py                 Evidence schemas, safe references, paginated tools
  reasoning/
    schemas.py               Structured evidence and verdict outputs
    prompts.py               Original English system prompts
    agents.py                Provider, models, and role-specific tools
    data.py                  Evidence loading and atomic output writes
    runtime.py               ReAct execution, retry handling, prompt builders
    pipeline.py              Parallel evidence barrier and batch processing
    reporting.py             Audit migration, timing, Token statistics, traces
    cli.py                   Analysis command-line interface
  resources/
    whitelist_packages_java.txt
tests/                       Offline regression tests
docs/                        Architecture, release notes, and manuscript
.env.example                 Variable names only; no credentials
```

The root scripts `dynamic_runner.py`, `trace_reducer.py`, and
`llm_multi_agent_reasoner_bing.py` remain compatible command-line entry points.
Python imports of the old monolithic implementation should migrate to the
corresponding package modules above.

## Installation

Use Python 3.10 or newer. The dependency versions in `pyproject.toml` match the
environment used for the release checks.

```bash
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install -e .
```

Dynamic collection additionally needs the Android SDK (`adb`, `aapt`, and
`emulator`), an initialized Android emulator with screenrecord and ART method
profiling support, and a compatible local DroidBot checkout. Install DroidBot's
dependencies in the same Python environment. Set `DROIDBOT_ROOT` to that checkout
or pass `--droidbot-root`. A specific DroidBot revision was not supplied with
the original source, so collection compatibility must be checked locally.

## Provider configuration

Export environment variables before starting Python. `.env.example` documents
the available variables; copying it to `.env` alone does not load it.

PowerShell:

```powershell
$env:MOIRAE_API_KEY = '<your-provider-key>'
$env:MOIRAE_BASE_URL = 'https://api.minimax.chat/v1'
$env:ANDROID_EVIDENCE_DATASET_ROOT = './data'
$env:VISION_AGENT_MODEL = 'MiniMax-M3'
$env:TEXT_AGENT_MODEL = 'MiniMax-M3'
$env:JUDGE_AGENT_MODEL = 'MiniMax-M3'
```

Bash:

```bash
export MOIRAE_API_KEY='<your-provider-key>'
export MOIRAE_BASE_URL='https://api.minimax.chat/v1'
export ANDROID_EVIDENCE_DATASET_ROOT='./data'
```

`MiniMax_API_KEY` and `MiniMax_BASE_URL` are accepted as legacy aliases. All
agents currently share one OpenAI-compatible endpoint and credential. A different
Judge model can be selected only if that endpoint serves it. The Vision model
must support image input and tool calls. Provider/model availability depends on
your account. Keep actual credentials outside Git; no fallback key is bundled.

## Workflow

### 1. Collect dynamic evidence

Use an emulator and test APKs prepared for your experiment. Configure paths for
the local SDK executables and use the benign/malware family layout consistently
across collection, reduction, and reasoning.

```bash
python dynamic_runner.py --apk-dir ./data/apks --serial emulator-5554 --seconds 120 --adb /path/to/adb --aapt /path/to/aapt --droidbot-root ./external/droidbot --droidbot-output-dir ./data/droidbot_out/benign --output-dir ./data/videos/droidbot/benign --trace-output-dir ./data/traces/droidbot/benign --xml-output-dir ./data/xml_states/droidbot/benign
```

The runner installs and launches APKs, records video and ART traces, runs DroidBot
actions, parses semantic events, and cleans up each app. Automatic clean-snapshot
recovery is enabled by default. `--recovery-mode wipe-data` erases the selected
AVD's data; use it only with an expendable experiment emulator. `--help` lists
recording, snapshot, and recovery options.

### 2. Reduce and align traces

```bash
python trace_reducer.py --trace ./data/traces/droidbot/benign --semantic-json ./data/xml_states/droidbot/benign --output-dir ./data/agent_workspace/benign
```

The reducer uses the bundled Java namespace allowlist and preserves trace
availability status. Empty or missing method traces remain explicit limitations.

### 3. Run the evidence agents and Judge

```bash
python llm_multi_agent_reasoner_bing.py --agent-report ./data/agent_workspace/benign --output-dir ./outputs/reasoning
```

Pass one fused JSON file or a directory containing JSON files. Directory collection
is nonrecursive: run each split/family directory separately. Evidence lookup uses
`ANDROID_EVIDENCE_DATASET_ROOT`; `--agent-report` does not replace that root.

Expected evidence layouts:

```text
data/
  droidbot_out/benign/<apk_name>/states/...
  droidbot_out/benign/<apk_name>/events/...
  xml_states/droidbot/benign/<apk_name>/xml_semantic_stream.json
  traces/droidbot/benign/<apk_name>.trace
  agent_workspace/benign/<apk_name>.json
```

For malware, insert the same family directory after `malware` in the DroidBot,
XML, trace, and workspace paths. Screenshots should remain alongside their native
DroidBot state files. See [architecture](docs/architecture.md) for execution and
output details.

### 4. Rebuild reports without a model call

```bash
python llm_multi_agent_reasoner_bing.py --output-dir ./outputs/reasoning --rebuild-output-only
```

This rebuilds aggregate documents from existing audit files. It does not rerun a
failed Judge or recover missing model output. Normal batch processing resumes
successful report records and processes unresolved samples; it can rerun evidence
agents for a failed sample.

## Outputs

| File/directory | Contents |
|---|---|
| `multi_agent_analysis_reports.json` | Compact verdicts, evidence chains, and status |
| `all_apks_multi_agent_context.json` | Final evidence-agent summaries |
| `all_apks_multi_agent_detailed_context.json` | Detailed per-sample evidence context |
| `multi_agent_audits/` | Prompts, model messages, decisions, retry and usage data |
| `multi_agent_traces/` | Per-sample human-readable traces |
| `llm_multi_agent_trace_full.md` | Combined trace document |
| `timing_stats.json` | Stage times, critical path, cumulative time, and usage |

Always filter `status == "success"` when evaluating predictions. An unresolved
Judge can retain a fallback `is_malicious: false`; that flag is not a valid benign
prediction. Missing/empty evidence is not proof of benign behavior. Provider Token
usage may be unavailable and is represented as missing rather than zero.

## Offline checks

```bash
python -m compileall -q moirae
python -m unittest discover -s tests -v
python dynamic_runner.py --help
python trace_reducer.py --help
python llm_multi_agent_reasoner_bing.py --help
```

The tests use synthetic evidence and PydanticAI's local test model. They do not
send APK data to a provider or require an emulator. Real-provider and Android
collection execution are separate integration steps.

See [release notes](docs/release_notes.md) for the source cleanup and preserved
behavior. No software license is asserted by this cleanup; the repository owner
should select an appropriate license before granting redistribution terms.
