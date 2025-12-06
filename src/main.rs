//! Token Security Analyzer - Standalone Binary
//!
//! A command-line tool to analyze token usage and detect security risks
//! in your codebase.
//!
//! # Usage
//! ```bash
//! token-analyzer <TOKEN_NAME> [DIRECTORY] [OPTIONS]
//!
//! # Examples:
//! token-analyzer API_KEY                    # Scan current directory
//! token-analyzer API_KEY ./src              # Scan specific directory
//! token-analyzer API_KEY . --fast           # Quick scan
//! token-analyzer API_KEY . --thorough       # Complete scan
//! token-analyzer API_KEY . --json           # JSON output
//! ```

use anyhow::Result;
use std::env;
use std::path::{Path, PathBuf};
use std::time::Instant;
use token_analyzer::{AnalysisReport, AnalyzerConfig, RiskLevel, TokenSecurityAnalyzer};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    if let Err(e) = run() {
        eprintln!("❌ Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let first_arg = &args[1];

    // Handle help/version
    if first_arg == "--help" || first_arg == "-h" {
        print_usage();
        return Ok(());
    }
    if first_arg == "--version" || first_arg == "-V" {
        println!("token-analyzer {}", VERSION);
        return Ok(());
    }

    let token_name = first_arg;

    // Parse directory (default to current)
    let search_dir = if args.len() > 2 && !args[2].starts_with('-') {
        PathBuf::from(&args[2])
    } else {
        env::current_dir()?
    };

    // Parse options
    let mut config = AnalyzerConfig::default();
    let mut json_output = false;
    let mut verbose = false;

    for arg in args.iter().skip(2) {
        match arg.as_str() {
            "--fast" | "-f" => config = AnalyzerConfig::fast(),
            "--thorough" | "-t" => config = AnalyzerConfig::thorough(),
            "--json" | "-j" => json_output = true,
            "--verbose" | "-v" => verbose = true,
            "--hidden" => config.include_hidden = true,
            "--follow-links" => config.follow_symlinks = true,
            _ if arg.starts_with("--timeout=") => {
                if let Some(ms) = arg.strip_prefix("--timeout=") {
                    config.timeout_ms = ms.parse().unwrap_or(30_000);
                }
            }
            _ if arg.starts_with("--max-files=") => {
                if let Some(n) = arg.strip_prefix("--max-files=") {
                    config.max_files = n.parse().unwrap_or(10_000);
                }
            }
            _ if arg.starts_with('-') => {
                eprintln!("⚠️  Unknown option: {}", arg);
            }
            _ => {}
        }
    }

    // Run analysis
    if verbose {
        eprintln!(
            "🔍 Analyzing token '{}' in {}",
            token_name,
            search_dir.display()
        );
        eprintln!(
            "   Config: max_files={}, timeout={}ms",
            if config.max_files == 0 {
                "unlimited".to_string()
            } else {
                config.max_files.to_string()
            },
            config.timeout_ms
        );
    }

    let start = Instant::now();
    let analyzer = TokenSecurityAnalyzer::new(config);
    let report = analyzer.analyze(token_name, &search_dir)?;

    if verbose {
        eprintln!(
            "   Scanned {} files in {:?}",
            report.files_scanned,
            start.elapsed()
        );
    }

    // Output
    if json_output {
        print_json(&report)?;
    } else {
        print_report(&report);
    }

    // Exit with error code if security issues found
    if report.has_security_issues() {
        std::process::exit(2);
    }

    Ok(())
}

fn print_usage() {
    println!(
        r#"
Token Security Analyzer v{}

Scan your codebase for token usage and detect potential security risks
like plaintext exposure in logs, prints, or debug statements.

Part of the lazy-locker ecosystem: https://github.com/WillIsback/lazy-locker

USAGE:
    token-analyzer <TOKEN_NAME> [DIRECTORY] [OPTIONS]

ARGUMENTS:
    <TOKEN_NAME>     The token/secret name to search for (e.g., API_KEY)
    [DIRECTORY]      Directory to scan (default: current directory)

OPTIONS:
    -f, --fast       Quick scan (1k files, 5s timeout)
    -t, --thorough   Complete scan (unlimited files, includes hidden)
    -j, --json       Output results as JSON
    -v, --verbose    Show progress and debug info
    --hidden         Include hidden files
    --follow-links   Follow symbolic links
    --timeout=MS     Set timeout in milliseconds (default: 30000)
    --max-files=N    Maximum files to scan (default: 10000, 0=unlimited)
    -h, --help       Print help
    -V, --version    Print version

EXAMPLES:
    token-analyzer API_KEY
    token-analyzer DATABASE_URL ./src --fast
    token-analyzer SECRET_KEY . --thorough --json
    token-analyzer AWS_ACCESS_KEY /path/to/project --verbose

EXIT CODES:
    0    No security issues found
    1    Error occurred
    2    Security issues detected (token exposed in logs/prints)

DETECTED PATTERNS:
    ⚠️  print(), println!(), printf(), echo
    ⚠️  console.log(), console.info(), console.error()
    ⚠️  logging.info(), logger.debug(), log.warn()
    ⚠️  format!(), f-strings with token values

RISK LEVELS:
    🔴 Critical - .env files, secrets, credentials, private keys
    🟠 High     - docker-compose, terraform, kubernetes configs
    🟡 Medium   - YAML, TOML, INI configuration files
    🟢 Low      - Regular source code files

KNOWN TOKEN PREFIXES:
    GitHub (ghp_), AWS (AKIA), Slack (xoxb-), Stripe (sk_live_),
    OpenAI (sk-), Google (AIza), HuggingFace (hf_), and more...
"#,
        VERSION
    );
}

fn risk_icon(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "🔴",
        RiskLevel::High => "🟠",
        RiskLevel::Medium => "🟡",
        RiskLevel::Low => "🟢",
    }
}

fn print_report(report: &AnalysisReport) {
    println!();
    println!("╭─────────────────────────────────────────────────────────────╮");
    println!("│  🔐 Token Security Analysis Report                          │");
    println!("╰─────────────────────────────────────────────────────────────╯");
    println!();
    println!("  Token:     {}", report.token_name);
    println!("  Directory: {}", report.search_dir.display());
    println!("  Duration:  {:?}", report.duration);
    println!("  Files:     {} scanned", report.files_scanned);
    if report.truncated {
        println!("  ⚠️  Analysis was truncated (limit reached)");
    }
    println!();

    if report.total_calls == 0 {
        println!("  ✅ No occurrences of '{}' found.", report.token_name);
        return;
    }

    // Summary
    println!("╭─────────────────────────────────────────────────────────────╮");
    println!("│  📊 Summary                                                  │");
    println!("╰─────────────────────────────────────────────────────────────╯");
    println!();
    println!(
        "  Total calls:  {} in {} files",
        report.total_calls,
        report.files.len()
    );
    println!(
        "  Risk score:   {} (critical files: {})",
        report.total_risk_score, report.critical_files
    );

    if report.exposure_count > 0 {
        println!(
            "  ⚠️  EXPOSED:   {} files with potential plaintext exposure!",
            report.exposure_count
        );
    } else {
        println!("  ✅ Secure:    No plaintext exposure detected");
    }
    println!();

    // Files list
    println!("╭─────────────────────────────────────────────────────────────╮");
    println!("│  📁 Files                                                    │");
    println!("╰─────────────────────────────────────────────────────────────╯");
    println!();

    for file in report.files_sorted() {
        let risk = risk_icon(&file.risk_level);
        let exposure_icon = if file.has_exposure { "⚠️ " } else { "   " };

        // Shorten path for display
        let display_path = shorten_path(&file.path, 45);

        // Build exposure details
        let exposure_info = if file.has_exposure {
            let types: Vec<String> = file
                .exposures
                .iter()
                .map(|e| format!("L{}: {}", e.line, e.exposure_type))
                .collect();
            format!(" [{}]", types.join(", "))
        } else {
            String::new()
        };

        println!(
            "{} {} {} ({} calls, score: {}){}",
            risk, exposure_icon, display_path, file.call_count, file.risk_score, exposure_info
        );
    }

    println!();

    // Security recommendations
    if report.has_security_issues() {
        println!("╭─────────────────────────────────────────────────────────────╮");
        println!("│  🛡️  Security Recommendations                               │");
        println!("╰─────────────────────────────────────────────────────────────╯");
        println!();
        println!("  The following files expose token values:");
        println!();

        for file in report.exposed_files() {
            println!(
                "  {} → {}",
                risk_icon(&file.risk_level),
                file.path.display()
            );
            for exposure in &file.exposures {
                println!(
                    "      Line {}: {} - {}",
                    exposure.line, exposure.exposure_type, exposure.context
                );
            }
        }

        println!();
        println!("  💡 Tips:");
        println!("     • Never log or print secret values directly");
        println!("     • Use '[REDACTED]' or mask tokens in debug output");
        println!("     • Never commit .env files or hardcoded secrets");
        println!("     • Consider using lazy-locker for secure secret management");
        println!("       https://github.com/WillIsback/lazy-locker");
        println!();
    }
}

fn print_json(report: &AnalysisReport) -> Result<()> {
    let json = serde_json::json!({
        "token_name": report.token_name,
        "search_dir": report.search_dir.display().to_string(),
        "total_calls": report.total_calls,
        "exposure_count": report.exposure_count,
        "total_risk_score": report.total_risk_score,
        "critical_files": report.critical_files,
        "has_security_issues": report.has_security_issues(),
        "files_scanned": report.files_scanned,
        "duration_ms": report.duration.as_millis(),
        "truncated": report.truncated,
        "files": report.files.iter().map(|f| {
            serde_json::json!({
                "path": f.path.display().to_string(),
                "call_count": f.call_count,
                "has_exposure": f.has_exposure,
                "risk_level": format!("{:?}", f.risk_level),
                "risk_score": f.risk_score,
                "exposures": f.exposures.iter().map(|e| {
                    serde_json::json!({
                        "line": e.line,
                        "type": format!("{}", e.exposure_type),
                        "context": e.context,
                    })
                }).collect::<Vec<_>>(),
                "exposure_lines": f.exposure_lines,
                "occurrence_lines": f.occurrence_lines,
            })
        }).collect::<Vec<_>>(),
        "errors": report.errors,
    });

    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn shorten_path(path: &Path, max_len: usize) -> String {
    let s = path.display().to_string();
    if s.len() <= max_len {
        s
    } else {
        format!("...{}", &s[s.len() - max_len + 3..])
    }
}
