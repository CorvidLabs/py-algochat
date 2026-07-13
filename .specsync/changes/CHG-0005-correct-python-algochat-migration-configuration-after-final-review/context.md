---
change: CHG-0005-correct-python-algochat-migration-configuration-after-final-review
artifact: context
---

# Context

Final review found four configuration defects: the clean Fledge install task did not install Ruff; the meaningful-path list omitted canonical specs and agent integration directories; Gemini rendered its arguments for display but passed an unsupported shell variable to `change new`; and all create-spec prompts consumed the first word before deciding whether the user supplied a bare module name or a natural-language description. None affects AlgoChat runtime behavior.
