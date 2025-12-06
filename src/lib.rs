//! # Token Security Analyzer
//!
//! Fast, parallel token security analyzer for detecting exposed secrets,
//! API keys, and sensitive tokens in your codebase.
//!
//! [![Crates.io](https://img.shields.io/crates/v/token-analyzer.svg)](https://crates.io/crates/token-analyzer)
//! [![Documentation](https://docs.rs/token-analyzer/badge.svg)](https://docs.rs/token-analyzer)
//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
//!
//! ## Features
//!
//! - **🚀 Blazing fast**: Uses ripgrep's `ignore` crate for file walking
//! - **⚡ Parallel**: Leverages `rayon` for multi-threaded file scanning
//! - **🧠 Smart**: Respects `.gitignore` and common ignore patterns
//! - **🔐 Security-focused**: Detects dangerous patterns (print, log, echo)
//! - **📁 Context-aware**: Prioritizes sensitive files (.env, configs)
//! - **🎯 Entropy detection**: Identifies high-entropy strings (real secrets)
//! - **🏷️ Known prefixes**: Detects known token formats (AWS, GitHub, Slack...)
//!
//! ## Quick Start
//!
//! ### As a library
//!
//! ```rust
//! use token_analyzer::{TokenSecurityAnalyzer, AnalyzerConfig};
//! use std::path::PathBuf;
//!
//! let analyzer = TokenSecurityAnalyzer::new(AnalyzerConfig::default());
//! let report = analyzer.analyze("API_KEY", &PathBuf::from(".")).unwrap();
//!
//! println!("Found {} calls in {} files", report.total_calls, report.files.len());
//! for file in &report.files {
//!     if file.has_exposure {
//!         println!("⚠️  {} - EXPOSED! (risk: {:?})", file.path.display(), file.risk_level);
//!     }
//! }
//! ```
//!
//! ### As a CLI tool
//!
//! ```bash
//! # Install
//! cargo install token-analyzer
//!
//! # Basic usage
//! token-analyzer API_KEY ./my-project
//!
//! # Quick scan
//! token-analyzer API_KEY ./my-project --fast
//!
//! # Thorough scan with JSON output
//! token-analyzer API_KEY ./my-project --thorough --json
//! ```
//!
//! ## Related Projects
//!
//! - [lazy-locker](https://github.com/WillIsback/lazy-locker) - Secure TUI secret manager
//!   that uses token-analyzer for security audits
//!
//! ## License
//!
//! MIT License - see [LICENSE](LICENSE) for details.

mod analyzer;

pub use analyzer::*;
