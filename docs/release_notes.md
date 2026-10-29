# Source cleanup

- Replaced embedded credentials and credential-bearing comments with environment
  variables. No original credentials were committed.
- Replaced machine-specific Windows paths and dataset-year defaults with portable
  paths, environment configuration, and existing CLI overrides.
- Translated Chinese source comments and docstrings into English. Runtime APK
  evidence can contain arbitrary languages; evidence itself is not translated.
- Split the monolithic reasoning script into schemas, prompts, agent construction,
  evidence loading, runtime utilities, pipeline, reporting, and CLI modules.
- Grouped collection, preprocessing, evidence tools, and namespace resources.
- Included the two locally required DroidBot helper modules absent from the
  original release directory.
- Retained the original English prompts, output schemas, tool policies, retry
  behavior, and parallel evidence/single-Judge execution strategy.
- Kept the three original script filenames as CLI wrappers. Internal Python API
  imports should migrate to the new modules.
- Preserved the supplied manuscript as `docs/Moirae.pdf` without editing its content.

Only code and documentation are prepared for Git publication. Local credentials,
datasets, APKs, traces, videos, and generated analysis reports are excluded.
