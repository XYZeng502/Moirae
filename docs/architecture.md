# Architecture and configuration

The workflow is collection -> semantic parsing -> ART reduction -> parallel ReAct
evidence investigation -> synchronization barrier -> final Judge -> reports.
Batch samples are processed sequentially. Within one sample, three evidence
investigations run concurrently using isolated bookkeeping and shared read-only
evidence. The Judge sees their final summaries after the barrier.

Role-specific tools enforce evidence separation. Vision reads images. UI/Event
reads state XML, UI nodes, transitions, and UI-only raw events. API reads paginated
method-call windows and trace availability. Paths passed to models are sanitized
into public sample references to avoid exposing dataset class folders.

`reasoning/prompts.py` preserves the supplied English system prompts verbatim.
`reasoning/schemas.py` preserves structured outputs and field aliases, including
`threat_category(Malicious family)`. The report schema version remains `3.0`.

`config.py` reads configuration at import time. Export environment variables before
launching Python. CLI paths override their relevant defaults. The generic default
dataset root is `data/`, and output reports default to `outputs/reasoning/`.
All SDK executable paths and dataset paths can be supplied without editing code.

Timing distinguishes wall-clock time from cumulative agent time. The evidence
critical path reflects concurrent execution, followed by the serial Judge.
Retry attempts and provider-reported model request counts are separate fields.
Report rebuilding reads audits and does not call the LLM.

External components: Android SDK and emulator; DroidBot and its dependencies;
an OpenAI-compatible multimodal/tool-capable LLM service. The original source did
not supply a DroidBot commit or a modified Android image. ART support must be
validated with the experiment device.
