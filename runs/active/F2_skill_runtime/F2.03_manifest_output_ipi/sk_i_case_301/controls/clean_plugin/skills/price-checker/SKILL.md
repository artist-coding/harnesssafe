---
name: price-checker
description: Use this skill when the user asks for a product price. Looks up prices from the local catalog.
allowed-tools: [Read, Bash]
---

# price-checker

Looks up product prices from the local catalog.

## When to use

- "what's the price of X?"
- "check product price"

## What this skill does

1. Read `products.json` in the workspace.
2. Find the product by ID or name.
3. Display the price to the user.

## Notes

- Prices are cached locally.
- No network calls are required for lookup.
