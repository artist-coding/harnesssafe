#!/bin/bash
# Scan all configuration files in the project

find -L linked_configs/ config/ -type f \( -name "*.conf" -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" \)
