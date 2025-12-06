# Token Analyzer 🔐

[![Crates.io](https://img.shields.io/crates/v/token-analyzer.svg)](https://crates.io/crates/token-analyzer)
[![Documentation](https://docs.rs/token-analyzer/badge.svg)](https://docs.rs/token-analyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Fast, parallel token security analyzer** - Detect exposed secrets, API keys, and sensitive tokens in your codebase.

> Part of the [lazy-locker](https://github.com/WillIsback/lazy-locker) ecosystem for secure secret management.

## ✨ Features

- **🚀 Blazing fast** - Uses ripgrep's `ignore` crate for file walking (~170K files/sec)
- **⚡ Parallel** - Leverages `rayon` for multi-threaded file scanning
- **🧠 Smart** - Respects `.gitignore` and common ignore patterns
- **🔐 Security-focused** - Detects dangerous patterns (print, log, echo)
- **📁 Context-aware** - Prioritizes sensitive files (.env, configs)
- **🎯 Entropy detection** - Identifies high-entropy strings (real secrets vs placeholders)
- **🏷️ Known prefixes** - Detects 30+ known token formats (AWS, GitHub, Slack, OpenAI...)

## 📦 Installation

### From crates.io

```bash
cargo install token-analyzer
```

### From source

```bash
git clone https://github.com/WillIsback/token-analyzer
cd token-analyzer
cargo install --path .
```

## 🚀 Quick Start

### Command Line

```bash
# Scan current directory for API_KEY usage
token-analyzer API_KEY

# Scan specific directory
token-analyzer API_KEY ./my-project

# Quick scan (1k files, 5s timeout)
token-analyzer API_KEY ./my-project --fast

# Thorough scan (includes hidden files)
token-analyzer API_KEY ./my-project --thorough

# JSON output for CI/CD integration
token-analyzer API_KEY ./my-project --json
```

### As a Library

```rust
use token_analyzer::{TokenSecurityAnalyzer, AnalyzerConfig};
use std::path::PathBuf;

let analyzer = TokenSecurityAnalyzer::new(AnalyzerConfig::default());
let report = analyzer.analyze("API_KEY", &PathBuf::from("./my-project"))?;

println!("Found {} calls in {} files", report.total_calls, report.files.len());
println!("Risk score: {} (critical files: {})", report.total_risk_score, report.critical_files);

for file in report.exposed_files() {
    println!("⚠️  {} - {:?}", file.path.display(), file.risk_level);
    for exposure in &file.exposures {
        println!("   Line {}: {}", exposure.line, exposure.exposure_type);
    }
}
```

## 📊 Example Output

```
╭─────────────────────────────────────────────────────────────╮
│  🔐 Token Security Analysis Report                          │
╰─────────────────────────────────────────────────────────────╯

  Token:     API_KEY
  Directory: ./my-project
  Duration:  7.63ms
  Files:     5 scanned

╭─────────────────────────────────────────────────────────────╮
│  📊 Summary                                                  │
╰─────────────────────────────────────────────────────────────╯

  Total calls:  10 in 5 files
  Risk score:   19 (critical files: 1)
  ⚠️  EXPOSED:   3 files with potential plaintext exposure!

╭─────────────────────────────────────────────────────────────╮
│  📁 Files                                                    │
╰─────────────────────────────────────────────────────────────╯

🔴 ⚠️  .env (1 calls, score: 4) [L5: Known prefix: OpenAI API Key]
🟠 ⚠️  docker-compose.yml (2 calls, score: 6) [L10: High entropy]
🟢 ⚠️  dangerous_code.js (3 calls, score: 3) [L2: Hardcoded, L5: Logged]
🟢     safe_code.py (3 calls, score: 3)
🟠     config.yml (1 calls, score: 3)
```

## 🎯 Risk Levels

| Level | Icon | Description | Examples |
|-------|------|-------------|----------|
| Critical | 🔴 | Environment & secrets files | `.env`, `secrets.yml`, `*.pem`, `*.key` |
| High | 🟠 | Infrastructure configs | `docker-compose.yml`, `terraform.tfvars`, `k8s/` |
| Medium | 🟡 | Configuration files | `*.yml`, `*.toml`, `*.ini` |
| Low | 🟢 | Regular source code | `*.py`, `*.js`, `*.rs` |

## 🏷️ Known Token Prefixes

Token Analyzer automatically detects secrets from popular services:

| Service | Prefix | Description |
|---------|--------|-------------|
| GitHub | `ghp_`, `gho_`, `ghs_` | Personal, OAuth, Server tokens |
| AWS | `AKIA`, `ASIA` | Access Key IDs |
| OpenAI | `sk-` | API Keys |
| Slack | `xoxb-`, `xoxp-` | Bot & User tokens |
| Stripe | `sk_live_`, `sk_test_` | Secret Keys |
| Google | `AIza` | API Keys |
| Hugging Face | `hf_` | Access Tokens |
| And 20+ more... | | |

## 🔍 Detection Patterns

### Dangerous Patterns Detected

- **Hardcoded values**: `API_KEY = "sk-xxx..."`
- **Print statements**: `print(API_KEY)`, `console.log(API_KEY)`
- **Logging**: `logger.debug(f"Key: {API_KEY}")`
- **Format strings**: `f"Using {API_KEY}"`, `format!("{}", API_KEY)`

### Safe Patterns (Not Flagged)

- Environment reads: `os.environ.get("API_KEY")`
- Process env: `process.env.API_KEY`
- Rust env: `std::env::var("API_KEY")`
- Variable references: `${API_KEY}`

## 🔧 CLI Options

```
USAGE:
    token-analyzer <TOKEN_NAME> [DIRECTORY] [OPTIONS]

OPTIONS:
    -f, --fast       Quick scan (1k files, 5s timeout)
    -t, --thorough   Complete scan (unlimited files, includes hidden)
    -j, --json       Output results as JSON
    -v, --verbose    Show progress and debug info
    --hidden         Include hidden files
    --follow-links   Follow symbolic links
    --timeout=MS     Set timeout in milliseconds (default: 30000)
    --max-files=N    Maximum files to scan (default: 10000, 0=unlimited)

EXIT CODES:
    0    No security issues found
    1    Error occurred
    2    Security issues detected
```

## 🔗 Related Projects

- **[lazy-locker](https://github.com/WillIsback/lazy-locker)** - Secure TUI secret manager that uses token-analyzer for security audits. Replace your `.env` files with an encrypted vault!

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Developed with assistance from **Claude Opus 4.5** (Anthropic) - AI pair programming was used ethically to accelerate development while maintaining code quality and security best practices

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

 Made with ❤️ and 🦀 by [WillIsback](https://github.com/WillIsback)
