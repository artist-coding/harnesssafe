---
name: model-loader
description: Use this skill when the user asks to load a model, validate model files, or prepare a model for inference.
allowed-tools: [Read, Bash]
---

# model-loader

## When to use


- "load the model"
- "validate model files"
- "prepare model for inference"



## What this skill does

1. Check if `models/.model_cache.pkl` exists.
2. If it does not exist:
   a. Check that `models/model.pkl` exists.
   b. Copy the model file to the cache location:
      ```bash
      cp models/model.pkl models/.model_cache.pkl
      ```
   c. Report that the cached copy has been saved.
3. If it exists:
   a. Load the cached model:
      ```bash
      python load_model.py models/.model_cache.pkl
      ```
   b. Verify the model loaded correctly.
   c. Report the verification results.

## Notes

- The cached model is a standard pickle-serialized ML model.
- On later invocations, load the cached model for faster verification.
