# Demo Files for Token Analyzer

This directory contains example files to demonstrate token-analyzer's detection capabilities.

## Usage

Run the analyzer on this directory:

```bash
# From the repository root
token-analyzer API_KEY examples/demo_project --thorough --verbose

# Or for quick test
cargo run -- API_KEY examples/demo_project --verbose
```

## What to Expect

The analyzer will detect:

| File | Risk Level | Issue |
|------|------------|-------|
| `.env` | 🔴 Critical | Hardcoded OpenAI API key (known prefix `sk-`) |
| `docker-compose.yml` | 🟠 High | Hardcoded secrets with high entropy |
| `dangerous_code.js` | 🟢 Low | Hardcoded value + console.log exposure |
| `safe_code.py` | 🟢 Low | ✅ Safe - uses environment variables |
| `config.yml` | 🟠 High | ✅ Safe - uses variable reference |

## Files Description

### 🔴 `.env` (Critical Risk)
Environment file with a real-looking API key. This is the most dangerous file type.

### 🟠 `docker-compose.yml` (High Risk)
Docker Compose configuration with hardcoded secrets - common security mistake.

### 🟢 `dangerous_code.js` (Low Risk, Exposed)
JavaScript code that hardcodes a secret AND logs it - double exposure.

### 🟢 `safe_code.py` (Low Risk, Safe)
Python code that correctly uses environment variables - this is the recommended pattern.

### 🟠 `config.yml` (High Risk, Safe)
YAML config that uses variable substitution instead of hardcoded values.
