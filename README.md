<div align="center">

# Moirae

### A Multimodal Agent Collaborative Framework<br>for Dynamic Android Malware Detection

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10 or newer">
  <img src="https://img.shields.io/badge/PydanticAI-2.7.0-6D5ACF" alt="PydanticAI 2.7.0">
  <img src="https://img.shields.io/badge/Agents-3%20Evidence%20%2B%201%20Judge-0F766E" alt="Three evidence agents and one Judge">
</p>

**Screenshots · UI States · Interaction Events · ART Traces**

[Overview](#overview) · [Framework](#framework) · [Quick Start](#quick-start) · [Workflow](#workflow) · [Outputs](#outputs) · [Project Structure](#project-structure)

</div>

---

## Overview

Moirae investigates Android runtime behavior through three independent ReAct
agents. They examine complementary evidence in parallel, then a final Judge
combines their findings into a structured verdict and an evidence chain.

| Agent | Evidence | Investigation focus |
| :--- | :--- | :--- |
| **Vision** | Runtime screenshots | Visual intent, impersonation, and deceptive interfaces |
| **UI/Event** | UI states and interaction events | State transitions, action causality, and external focus changes |
| **API** | ART method traces | Sensitive calls and observed runtime behavior |
| **Judge** | Final reports from all three evidence agents | Cross-view reasoning and the final verdict |

Each evidence agent completes its own whole-APK investigation. The Judge starts
after all three finish. Audits retain prompts, model messages, retry records,
timing, and available Token usage.

## Framework

<p align="center">
  <img src="docs/moirae-framework.png" alt="Moirae framework: dynamic preprocessing, three evidence investigations, and final judgment" width="1100">
</p>
<p align="center"><em>Dynamic evidence collection → independent multimodal investigations → final judgment.</em></p>

## Quick Start

### 1. Install

Use **Python 3.10 or newer**. Dependencies are specified in
[`pyproject.toml`](pyproject.toml).

```bash
git clone https://github.com/XYZeng502/Moirae.git
cd Moirae
python -m venv .venv
```

| Shell | Activate the environment |
| :--- | :--- |
| Bash / Zsh | `source .venv/bin/activate` |
| PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Windows Command Prompt | `.venv\Scripts\activate.bat` |

```bash
python -m pip install -e .
```

### 2. Configure the provider

Export configuration **before starting Python**.
The [configuration template](.env.example) lists the available variables;
`.env` files are not loaded automatically.

<details open>
<summary><strong>PowerShell</strong></summary>

```powershell
$env:MOIRAE_API_KEY = '<your-provider-key>'
$env:MOIRAE_BASE_URL = 'https://api.minimax.chat/v1'
$env:ANDROID_EVIDENCE_DATASET_ROOT = './data'
$env:VISION_AGENT_MODEL = 'MiniMax-M3'
$env:TEXT_AGENT_MODEL = 'MiniMax-M3'
$env:JUDGE_AGENT_MODEL = 'MiniMax-M3'
```

</details>

<details>
<summary><strong>Bash / Zsh</strong></summary>

```bash
export MOIRAE_API_KEY='<your-provider-key>'
export MOIRAE_BASE_URL='https://api.minimax.chat/v1'
export ANDROID_EVIDENCE_DATASET_ROOT='./data'
export VISION_AGENT_MODEL='MiniMax-M3'
export TEXT_AGENT_MODEL='MiniMax-M3'
export JUDGE_AGENT_MODEL='MiniMax-M3'
```

</details>

All agents share one OpenAI-compatible endpoint and credential. The endpoint must
serve the selected models; Vision requires image input and tool calls. Legacy
`MiniMax_API_KEY` and `MiniMax_BASE_URL` remain supported. APKs, collected data,
generated reports, credentials, the Android SDK, and DroidBot are not bundled.

### 3. Analyze prepared evidence

If fused reports and their associated runtime evidence are already available:

```bash
moirae-analyze --agent-report ./data/agent_workspace/benign --output-dir ./outputs/reasoning
```

For a new APK dataset, start with the full workflow below.

## Workflow

| Stage | Command | Result |
| :--- | :--- | :--- |
| **1 · Collect** | `moirae-collect` | Screenshots, UI/event records, video, and ART traces |
| **2 · Align** | `moirae-reduce` | Fused event-window and API evidence reports |
| **3 · Analyze** | `moirae-analyze` | Agent investigations, verdicts, and audit reports |

### 1. Collect dynamic evidence

Collection requires the Android SDK (`adb`, `aapt`, and `emulator`), a test
emulator with screen recording and ART method profiling, and a compatible
DroidBot checkout. Install DroidBot's dependencies in the same Python environment.
Set `DROIDBOT_ROOT` or pass `--droidbot-root`. The original experiment did not
specify a DroidBot revision or bundle a modified Android image.

<details>
<summary><strong>Collection command · Bash</strong></summary>

```bash
moirae-collect \
  --apk-dir ./data/apks \
  --serial emulator-5554 \
  --seconds 120 \
  --adb /path/to/adb \
  --aapt /path/to/aapt \
  --droidbot-root ./external/droidbot \
  --droidbot-output-dir ./data/droidbot_out/benign \
  --output-dir ./data/videos/droidbot/benign \
  --trace-output-dir ./data/traces/droidbot/benign \
  --xml-output-dir ./data/xml_states/droidbot/benign
```

Replace the executable paths with your SDK locations. In PowerShell, run this
command on one line or replace Bash continuation characters with PowerShell backticks.

</details>

The runner handles installation, launch, recording, DroidBot actions, semantic
parsing, and cleanup. Clean-snapshot recovery is enabled by default.
`--recovery-mode wipe-data` erases the selected AVD's data; use an expendable
experiment emulator for that mode.

### 2. Reduce and align traces

```bash
moirae-reduce --trace ./data/traces/droidbot/benign --semantic-json ./data/xml_states/droidbot/benign --output-dir ./data/agent_workspace/benign
```

The reducer applies the bundled Java namespace allowlist and aligns method calls
with semantic event windows. Missing or empty traces retain their availability status.

### 3. Run the agents and Judge

```bash
moirae-analyze --agent-report ./data/agent_workspace/benign --output-dir ./outputs/reasoning
```

Supply one fused JSON file or a directory of JSON files. Discovery is nonrecursive,
so run each split/family directory separately. Evidence lookup uses
`ANDROID_EVIDENCE_DATASET_ROOT` independently of `--agent-report`.

<details>
<summary><strong>Expected evidence layout</strong></summary>

```text
data/
├── droidbot_out/benign/<apk_name>/
│   ├── states/...
│   └── events/...
├── xml_states/droidbot/benign/<apk_name>/xml_semantic_stream.json
├── traces/droidbot/benign/<apk_name>.trace
└── agent_workspace/benign/<apk_name>.json
```

For malware, use a matching family directory after `malware` across evidence
paths. Keep screenshots alongside their native DroidBot state files.

</details>

### Rebuild saved reports

```bash
moirae-analyze --output-dir ./outputs/reasoning --rebuild-output-only
```

Rebuilding uses saved audits and makes no model calls. Missing Judge outputs
require a new analysis run. Normal batch execution skips successful samples and
can rerun evidence agents for unresolved samples.

## Outputs

| Output | Contents |
| :--- | :--- |
| `multi_agent_analysis_reports.json` | Verdicts, confidence scores, evidence chains, and status |
| `all_apks_multi_agent_context.json` | Final summaries from the evidence agents |
| `all_apks_multi_agent_detailed_context.json` | Detailed evidence context |
| `multi_agent_audits/` | Prompts, messages, retries, decisions, and usage |
| `multi_agent_traces/` | Per-sample readable execution traces |
| `llm_multi_agent_trace_full.md` | Combined trace document |
| `timing_stats.json` | Stage durations, critical path, cumulative time, and Tokens |

> **Evaluation:** include only records with `status == "success"`.
> A failed Judge can retain a fallback `is_malicious: false`; it is not a valid
> benign verdict. Missing evidence is not proof of benign behavior.

Missing provider Token usage is recorded as unavailable. Wall-clock time accounts
for concurrent evidence agents; cumulative agent time sums their individual durations.

## Project Structure

<details>
<summary><strong>Explore the source modules</strong></summary>

```text
moirae/
├── config.py                  Paths, provider settings, and execution metadata
├── collection/
│   ├── runner.py              Emulator recording and APK lifecycle
│   ├── action_runner.py       DroidBot actions-only subprocess
│   └── state_parser.py        Semantic state and event extraction
├── preprocessing/
│   └── trace_reducer.py        ART filtering and event-window alignment
├── evidence/
│   └── tools.py               Role-specific evidence access and pagination
├── reasoning/
│   ├── schemas.py             Structured evidence and verdict models
│   ├── prompts.py             Evidence-agent and Judge system prompts
│   ├── agents.py              Models and tool registration
│   ├── data.py                Evidence loading and atomic output writes
│   ├── runtime.py             ReAct execution, retries, and prompt builders
│   ├── pipeline.py            Concurrent investigations and batch processing
│   ├── reporting.py           Audits, timing, Token statistics, and traces
│   └── cli.py                 Analysis command-line interface
└── resources/
    └── whitelist_packages_java.txt
docs/
└── moirae-framework.png        Framework figure
tests/                         Offline regression tests
.env.example                   Configuration template
pyproject.toml                 Dependencies and CLI entry points
```

</details>

## Verification

```bash
python -m compileall -q moirae
python -m unittest discover -s tests -v
```

Tests use synthetic evidence and local PydanticAI test models. They cover the
pipeline, sample resume, report rebuilding, isolated bookkeeping, namespace
matching, missing traces, and path sanitization without an emulator or paid API.

<details>
<summary><strong>Run CLI help directly from the source tree</strong></summary>

```bash
python -m moirae.collection.runner --help
python -m moirae.preprocessing.trace_reducer --help
python -m moirae.reasoning.cli --help
```

</details>

---

<p align="center"><strong>Moirae</strong> · Multimodal evidence, independent investigations, traceable decisions.</p>
