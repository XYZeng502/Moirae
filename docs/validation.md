# Release validation

Validated on 2026-10-29 using the local Python environment.

- Python compilation succeeded for the package modules.
- All three compatibility CLI help commands loaded successfully.
- Five offline regression tests passed: complete pipeline/report generation,
  successful-sample resume and report rebuild; independent agent bookkeeping;
  Java namespace boundary matching; missing-trace handling; private-path masking.
- A wheel built successfully using local tools with dependency downloads disabled.
- AST comparison confirmed that 78 original functions/classes retained their
  implementations through module extraction. Four original system prompts were
  compared as strings and remained identical.
- All release text files were checked for original embedded credentials,
  key-like strings, Chinese source text, and original machine-specific paths.

The tests use synthetic data and local test models. No live LLM inference or APK
emulator experiment was run as part of this source cleanup. The supplied PDF is
retained as a reference document and is outside the code/text cleanup scan.
