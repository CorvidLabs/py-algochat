---
change: CHG-0004-replace-generic-python-algochat-export-descriptions-with-precise-implementation
artifact: context
---

# Context

The active contract detects all 103 package exports, but its initial table assigned the same generic sentence to every symbol. Coverage was mechanically complete yet insufficient for a human reviewer to verify what each function, model, error, or wire constant governs. The implementation already provides stable docstrings and explicit constant values that support precise descriptions without changing runtime behavior.
