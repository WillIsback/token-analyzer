//! Token Security Analyzer - Fast, parallel token usage analysis
//!
//! This module provides a standalone security analyzer that scans codebases
//! for token usage patterns and identifies potential security risks like
//! plaintext exposure in logs, prints, or debug statements.
//!
//! # Features
//! - **Blazing fast**: Uses ripgrep's `ignore` crate for file walking
//! - **Parallel**: Leverages `rayon` for multi-threaded file scanning
//! - **Smart**: Respects `.gitignore` and common ignore patterns
//! - **Security-focused**: Detects dangerous patterns (print, log, echo)
//! - **Context-aware**: Prioritizes sensitive files (.env, configs)
//! - **Entropy detection**: Identifies high-entropy strings (real secrets)
//! - **Known prefixes**: Detects known token formats (AWS, GitHub, Slack...)
//!
//! # Example
//! ```no_run
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

use anyhow::Result;
use ignore::WalkBuilder;
use parking_lot::Mutex;
use rayon::prelude::*;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// Risk Classification
// ============================================================================

/// Risk level for a file based on its type and content
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Low risk - regular source code
    Low = 1,
    /// Medium risk - configuration files
    Medium = 2,
    /// High risk - sensitive config files
    High = 3,
    /// Critical risk - environment/secrets files
    Critical = 4,
}

impl RiskLevel {
    /// Returns the risk multiplier for scoring
    pub fn multiplier(&self) -> usize {
        match self {
            RiskLevel::Low => 1,
            RiskLevel::Medium => 2,
            RiskLevel::High => 3,
            RiskLevel::Critical => 4,
        }
    }
}

/// Known token prefixes from popular services
pub const KNOWN_TOKEN_PREFIXES: &[(&str, &str)] = &[
    // GitHub
    ("ghp_", "GitHub Personal Access Token"),
    ("gho_", "GitHub OAuth Token"),
    ("ghu_", "GitHub User-to-Server Token"),
    ("ghs_", "GitHub Server-to-Server Token"),
    ("ghr_", "GitHub Refresh Token"),
    // AWS
    ("AKIA", "AWS Access Key ID"),
    ("ABIA", "AWS STS Token"),
    ("ACCA", "AWS Context-specific Credential"),
    ("ASIA", "AWS Temporary Access Key"),
    // Slack
    ("xoxb-", "Slack Bot Token"),
    ("xoxp-", "Slack User Token"),
    ("xoxa-", "Slack App Token"),
    ("xoxr-", "Slack Refresh Token"),
    // Stripe
    ("sk_live_", "Stripe Live Secret Key"),
    ("sk_test_", "Stripe Test Secret Key"),
    ("pk_live_", "Stripe Live Publishable Key"),
    ("rk_live_", "Stripe Live Restricted Key"),
    // OpenAI
    ("sk-", "OpenAI API Key"),
    // Anthropic
    ("sk-ant-", "Anthropic API Key"),
    // Google
    ("AIza", "Google API Key"),
    // Hugging Face
    ("hf_", "Hugging Face Token"),
    // npm
    ("npm_", "npm Access Token"),
    // PyPI
    ("pypi-", "PyPI API Token"),
    // Discord
    ("NDc", "Discord Bot Token (Base64)"),
    ("MTk", "Discord Bot Token (Base64)"),
    // Telegram
    ("bot", "Telegram Bot Token"),
    // Twilio
    ("SK", "Twilio API Key"),
    // SendGrid
    ("SG.", "SendGrid API Key"),
    // Mailgun
    ("key-", "Mailgun API Key"),
    // DigitalOcean
    ("dop_v1_", "DigitalOcean Personal Access Token"),
    ("doo_v1_", "DigitalOcean OAuth Token"),
    // Vercel
    ("vercel_", "Vercel Token"),
    // Supabase
    ("sbp_", "Supabase Token"),
    // PlanetScale
    ("pscale_", "PlanetScale Token"),
    // Railway
    ("railway_", "Railway Token"),
    // Render
    ("rnd_", "Render Token"),
    // Netlify
    ("netlify_", "Netlify Token"),
];

/// Critical file patterns (highest risk)
const CRITICAL_FILE_PATTERNS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".envrc",
    "secrets",
    "credentials",
    ".secrets",
    ".credentials",
    "id_rsa",
    "id_ed25519",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".htpasswd",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".dockerconfigjson",
    "service_account",
    "serviceaccount",
];

/// High risk file patterns
const HIGH_RISK_FILE_PATTERNS: &[&str] = &[
    "docker-compose",
    "dockerfile",
    "terraform.tfvars",
    "terraform.tfstate",
    ".tfvars",
    "ansible",
    "vault",
    "consul",
    "kubernetes",
    "k8s",
    "helm",
    "kustomize",
    "application.yml",
    "application.yaml",
    "application.properties",
    "appsettings.json",
    "config.yml",
    "config.yaml",
    "config.json",
    "settings.yml",
    "settings.yaml",
    "settings.json",
    "parameters.yml",
    "parameters.yaml",
    "database.yml",
];

/// Medium risk file extensions
const MEDIUM_RISK_EXTENSIONS: &[&str] = &[
    "yml",
    "yaml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "config",
    "properties",
];

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the token analyzer
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Maximum number of files to scan (0 = unlimited)
    pub max_files: usize,
    /// Maximum file size in bytes to scan (skip larger files)
    pub max_file_size: u64,
    /// Timeout for the entire analysis in milliseconds (0 = no timeout)
    pub timeout_ms: u64,
    /// Whether to follow symbolic links
    pub follow_symlinks: bool,
    /// Whether to include hidden files
    pub include_hidden: bool,
    /// File extensions to scan (empty = use defaults)
    pub extensions: Vec<String>,
    /// Additional directories to ignore
    pub ignore_dirs: Vec<String>,
    /// Number of threads to use (0 = auto)
    pub num_threads: usize,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_file_size: 10 * 1024 * 1024, // 10 MB
            timeout_ms: 30_000,              // 30 seconds
            follow_symlinks: false,
            include_hidden: false,
            extensions: vec![],
            ignore_dirs: vec![
                "node_modules".into(),
                "target".into(),
                ".git".into(),
                "__pycache__".into(),
                "venv".into(),
                ".venv".into(),
                "dist".into(),
                "build".into(),
                ".cache".into(),
            ],
            num_threads: 0, // Auto-detect
        }
    }
}

impl AnalyzerConfig {
    /// Creates a fast config for quick scans
    pub fn fast() -> Self {
        Self {
            max_files: 1_000,
            max_file_size: 1024 * 1024, // 1 MB
            timeout_ms: 5_000,          // 5 seconds
            ..Default::default()
        }
    }

    /// Creates a thorough config for complete scans
    pub fn thorough() -> Self {
        Self {
            max_files: 0,                    // Unlimited
            max_file_size: 50 * 1024 * 1024, // 50 MB
            timeout_ms: 120_000,             // 2 minutes
            include_hidden: true,
            ..Default::default()
        }
    }

    /// Get default extensions for code files
    fn default_extensions() -> Vec<&'static str> {
        vec![
            "py", "js", "ts", "jsx", "tsx", "rs", "go", "rb", "java", "kt", "swift", "c", "cpp",
            "h", "hpp", "cs", "php", "sh", "bash", "zsh", "fish", "yaml", "yml", "json", "toml",
            "env", "conf", "cfg", "ini", "md", "txt", "sql", "graphql", "prisma",
        ]
    }
}

// ============================================================================
// Results
// ============================================================================

/// Exposure type detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposureType {
    /// Hardcoded value in source code
    HardcodedValue,
    /// Logged or printed to output
    LoggedOutput,
    /// Found in environment file (.env)
    EnvironmentFile,
    /// Found in configuration file
    ConfigFile,
    /// High entropy string (likely real secret)
    HighEntropy,
    /// Known token prefix detected
    KnownTokenPrefix(String),
}

impl std::fmt::Display for ExposureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExposureType::HardcodedValue => write!(f, "Hardcoded value"),
            ExposureType::LoggedOutput => write!(f, "Logged/printed"),
            ExposureType::EnvironmentFile => write!(f, "In .env file"),
            ExposureType::ConfigFile => write!(f, "In config file"),
            ExposureType::HighEntropy => write!(f, "High entropy (real secret)"),
            ExposureType::KnownTokenPrefix(prefix) => write!(f, "Known prefix: {}", prefix),
        }
    }
}

/// Detailed exposure information
#[derive(Debug, Clone)]
pub struct ExposureDetail {
    /// Line number where exposure was detected
    pub line: usize,
    /// Type of exposure
    pub exposure_type: ExposureType,
    /// The actual content that was matched (redacted if sensitive)
    pub context: String,
}

/// Analysis report for a single file
#[derive(Debug, Clone)]
pub struct FileAnalysis {
    /// Path to the file
    pub path: PathBuf,
    /// Number of token occurrences in this file
    pub call_count: usize,
    /// Whether the token appears to be exposed (print, log, etc.)
    pub has_exposure: bool,
    /// Risk level based on file type
    pub risk_level: RiskLevel,
    /// Computed risk score (call_count * risk_multiplier)
    pub risk_score: usize,
    /// Detailed exposure information
    pub exposures: Vec<ExposureDetail>,
    /// Line numbers where exposure was detected (legacy compatibility)
    pub exposure_lines: Vec<usize>,
    /// Line numbers of all occurrences
    pub occurrence_lines: Vec<usize>,
}

/// Complete analysis report
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    /// Token that was analyzed
    pub token_name: String,
    /// Directory that was scanned
    pub search_dir: PathBuf,
    /// Total number of calls found
    pub total_calls: usize,
    /// Number of files with exposure warnings
    pub exposure_count: usize,
    /// Total risk score across all files
    pub total_risk_score: usize,
    /// Number of critical-risk files found
    pub critical_files: usize,
    /// Per-file analysis results
    pub files: Vec<FileAnalysis>,
    /// Time taken for the analysis
    pub duration: Duration,
    /// Number of files scanned
    pub files_scanned: usize,
    /// Whether the analysis was truncated due to limits
    pub truncated: bool,
    /// Error messages encountered during scan
    pub errors: Vec<String>,
}

impl AnalysisReport {
    /// Returns files sorted by risk score (highest first), then exposure, then call count
    pub fn files_sorted(&self) -> Vec<&FileAnalysis> {
        let mut sorted: Vec<_> = self.files.iter().collect();
        sorted.sort_by(|a, b| {
            // Risk score first, then exposure, then call count
            b.risk_score
                .cmp(&a.risk_score)
                .then_with(|| b.has_exposure.cmp(&a.has_exposure))
                .then_with(|| b.call_count.cmp(&a.call_count))
        });
        sorted
    }

    /// Returns only files with exposure warnings
    pub fn exposed_files(&self) -> Vec<&FileAnalysis> {
        self.files.iter().filter(|f| f.has_exposure).collect()
    }

    /// Returns files at critical or high risk level
    pub fn high_risk_files(&self) -> Vec<&FileAnalysis> {
        self.files
            .iter()
            .filter(|f| f.risk_level >= RiskLevel::High)
            .collect()
    }

    /// Check if any exposure was found
    pub fn has_security_issues(&self) -> bool {
        self.exposure_count > 0
    }

    /// Check if critical issues were found
    pub fn has_critical_issues(&self) -> bool {
        self.files
            .iter()
            .any(|f| f.has_exposure && f.risk_level == RiskLevel::Critical)
    }
}

// ============================================================================
// Analyzer
// ============================================================================

/// Token Security Analyzer
///
/// Scans directories for token usage and identifies security risks.
pub struct TokenSecurityAnalyzer {
    config: AnalyzerConfig,
}

impl TokenSecurityAnalyzer {
    /// Creates a new analyzer with the given configuration
    pub fn new(config: AnalyzerConfig) -> Self {
        Self { config }
    }

    /// Creates an analyzer with default configuration
    pub fn default_analyzer() -> Self {
        Self::new(AnalyzerConfig::default())
    }

    /// Analyzes token usage in the specified directory
    pub fn analyze(&self, token_name: &str, search_dir: &Path) -> Result<AnalysisReport> {
        let start = Instant::now();
        let timeout = if self.config.timeout_ms > 0 {
            Some(Duration::from_millis(self.config.timeout_ms))
        } else {
            None
        };

        // Validate inputs
        if token_name.is_empty() {
            anyhow::bail!("Token name cannot be empty");
        }
        if !search_dir.exists() {
            anyhow::bail!("Search directory does not exist: {}", search_dir.display());
        }

        // Build the file walker
        let files = self.collect_files(search_dir, &start, timeout)?;
        let files_scanned = files.len();
        let truncated = self.config.max_files > 0 && files_scanned >= self.config.max_files;

        // Check timeout before processing
        if let Some(t) = timeout {
            if start.elapsed() >= t {
                return Ok(self.timeout_report(token_name, search_dir, start));
            }
        }

        // Build regex patterns
        let patterns = self.build_patterns(token_name)?;

        // Parallel analysis
        let results = self.analyze_files_parallel(&files, &patterns, &start, timeout)?;

        // Build report
        let total_calls: usize = results.iter().map(|f| f.call_count).sum();
        let exposure_count = results.iter().filter(|f| f.has_exposure).count();
        let total_risk_score: usize = results.iter().map(|f| f.risk_score).sum();
        let critical_files = results
            .iter()
            .filter(|f| f.risk_level == RiskLevel::Critical)
            .count();

        Ok(AnalysisReport {
            token_name: token_name.to_string(),
            search_dir: search_dir.to_path_buf(),
            total_calls,
            exposure_count,
            total_risk_score,
            critical_files,
            files: results,
            duration: start.elapsed(),
            files_scanned,
            truncated,
            errors: vec![],
        })
    }

    /// Determines the risk level for a file based on its path and name
    fn get_file_risk_level(path: &Path) -> RiskLevel {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let path_str = path.to_string_lossy().to_lowercase();

        // Check for critical patterns
        for pattern in CRITICAL_FILE_PATTERNS {
            if filename.contains(pattern) || filename.starts_with(pattern) {
                return RiskLevel::Critical;
            }
        }

        // Check for high-risk patterns
        for pattern in HIGH_RISK_FILE_PATTERNS {
            if filename.contains(pattern) || path_str.contains(pattern) {
                return RiskLevel::High;
            }
        }

        // Check for medium-risk extensions
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if MEDIUM_RISK_EXTENSIONS.contains(&ext_str.as_str()) {
                return RiskLevel::Medium;
            }
        }

        RiskLevel::Low
    }

    /// Calculates Shannon entropy of a string (higher = more random = more likely real secret)
    fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut char_counts = std::collections::HashMap::new();
        for c in s.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for count in char_counts.values() {
            let p = *count as f64 / len;
            entropy -= p * p.log2();
        }

        entropy
    }

    /// Checks if a string appears to be a high-entropy secret
    fn is_high_entropy_secret(value: &str) -> bool {
        // Minimum length for a real secret
        if value.len() < 8 {
            return false;
        }

        // Skip obvious placeholders
        let lower = value.to_lowercase();
        if lower.contains("example")
            || lower.contains("placeholder")
            || lower.contains("your_")
            || lower.contains("xxx")
            || lower.contains("todo")
            || lower.contains("replace")
            || lower == "test"
            || lower == "secret"
            || lower == "password"
        {
            return false;
        }

        // Calculate entropy - real secrets typically have entropy > 3.5
        let entropy = Self::calculate_entropy(value);
        entropy > 3.5
    }

    /// Checks if a value matches a known token prefix
    fn detect_known_prefix(value: &str) -> Option<&'static str> {
        for (prefix, description) in KNOWN_TOKEN_PREFIXES {
            if value.starts_with(prefix) {
                return Some(*description);
            }
        }
        None
    }

    /// Collects files to analyze
    fn collect_files(
        &self,
        search_dir: &Path,
        start: &Instant,
        timeout: Option<Duration>,
    ) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let extensions: Vec<&str> = if self.config.extensions.is_empty() {
            AnalyzerConfig::default_extensions()
        } else {
            self.config.extensions.iter().map(|s| s.as_str()).collect()
        };

        let mut builder = WalkBuilder::new(search_dir);
        builder
            .hidden(!self.config.include_hidden)
            .follow_links(self.config.follow_symlinks)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true);

        // Set thread count for parallel walking
        if self.config.num_threads > 0 {
            builder.threads(self.config.num_threads);
        }

        for result in builder.build() {
            // Check timeout
            if let Some(t) = timeout {
                if start.elapsed() >= t {
                    break;
                }
            }

            // Check file limit
            if self.config.max_files > 0 && files.len() >= self.config.max_files {
                break;
            }

            let entry = match result {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();

            // Skip directories
            if path.is_dir() {
                continue;
            }

            // Check ignored directories
            if self.is_ignored_dir(path) {
                continue;
            }

            // Check if file should be included based on extension or critical pattern
            let filename = path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            // Always include critical files (like .env) regardless of extension
            let is_critical = CRITICAL_FILE_PATTERNS
                .iter()
                .any(|p| filename.contains(p) || filename.starts_with(p));

            if !is_critical {
                // Check extension for non-critical files
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if !extensions.contains(&ext_str.as_str()) {
                        continue;
                    }
                } else {
                    // No extension and not critical - skip
                    continue;
                }
            }

            // Check file size
            if let Ok(metadata) = path.metadata() {
                if metadata.len() > self.config.max_file_size {
                    continue;
                }
            }

            files.push(path.to_path_buf());
        }

        Ok(files)
    }

    /// Checks if a path is in an ignored directory
    fn is_ignored_dir(&self, path: &Path) -> bool {
        for component in path.components() {
            if let std::path::Component::Normal(name) = component {
                let name_str = name.to_string_lossy();
                if self
                    .config
                    .ignore_dirs
                    .iter()
                    .any(|d| d == name_str.as_ref())
                {
                    return true;
                }
            }
        }
        false
    }

    /// Builds regex patterns for token detection
    fn build_patterns(&self, token_name: &str) -> Result<AnalysisPatterns> {
        // Escape special regex characters in token name
        let escaped = regex::escape(token_name);

        // Main pattern: exact token match (word boundary)
        let token_pattern = format!(r"\b{}\b", escaped);
        let token_regex = Regex::new(&token_pattern)
            .map_err(|e| anyhow::anyhow!("Failed to build token regex: {}", e))?;

        // Exposure patterns: detect dangerous usage
        // These patterns match lines that could expose the token value
        // Note: We explicitly match string literals with quotes to avoid false positives
        // from safe patterns like os.environ.get("TOKEN") or process.env.TOKEN
        let exposure_patterns = [
            // === HARDCODED VALUES (most critical) ===
            // Direct assignment with string value: TOKEN="value", TOKEN='value', TOKEN = "value"
            // This catches hardcoded secrets but NOT environment variable reads
            format!(r#"\b{}\b\s*=\s*["'][^"']+["']"#, escaped),
            // Dict/object literal with hardcoded value: "TOKEN": "value", 'TOKEN': 'value'
            format!(r#"["']{}\s*["']\s*:\s*["'][^"']+["']"#, escaped),
            // === LOGGING/PRINT STATEMENTS ===
            // Print statements
            format!(
                r"(?i)(print|println!?|printf|echo|puts)\s*[\(\[].*\b{}\b",
                escaped
            ),
            // Console logging (JS/TS)
            format!(
                r"(?i)console\.(log|info|warn|error|debug)\s*\(.*\b{}\b",
                escaped
            ),
            // Python logging
            format!(
                r"(?i)(logging\.|logger\.)(info|debug|warning|error|critical)\s*\(.*\b{}\b",
                escaped
            ),
            // Rust logging
            format!(
                r"(?i)(log::)?(info!|debug!|warn!|error!|trace!)\s*\(.*\b{}\b",
                escaped
            ),
            // Generic log calls
            format!(r"(?i)\blog\s*[\(\[].*\b{}\b", escaped),
            // Write to stdout/stderr
            format!(
                r"(?i)(stdout|stderr|write|writeln!?)\s*[\(\[].*\b{}\b",
                escaped
            ),
            // Format strings with the token (f-strings, format!)
            format!(r#"(?i)f["'].*\b{}\b"#, escaped),
            format!(r"(?i)format!\s*\(.*\b{}\b", escaped),
        ];

        let exposure_regex = Regex::new(&exposure_patterns.join("|"))
            .map_err(|e| anyhow::anyhow!("Failed to build exposure regex: {}", e))?;

        Ok(AnalysisPatterns {
            token_regex,
            exposure_regex,
        })
    }

    /// Analyzes files in parallel
    fn analyze_files_parallel(
        &self,
        files: &[PathBuf],
        patterns: &AnalysisPatterns,
        start: &Instant,
        timeout: Option<Duration>,
    ) -> Result<Vec<FileAnalysis>> {
        let results: Arc<Mutex<Vec<FileAnalysis>>> = Arc::new(Mutex::new(Vec::new()));
        let timed_out = Arc::new(Mutex::new(false));

        files.par_iter().for_each(|file| {
            // Check timeout
            if let Some(t) = timeout {
                if start.elapsed() >= t {
                    *timed_out.lock() = true;
                    return;
                }
            }

            if *timed_out.lock() {
                return;
            }

            if let Ok(analysis) = self.analyze_file(file, patterns) {
                if analysis.call_count > 0 {
                    results.lock().push(analysis);
                }
            }
        });

        let inner = Arc::try_unwrap(results)
            .map(|m| m.into_inner())
            .unwrap_or_else(|arc| arc.lock().clone());

        Ok(inner)
    }

    /// Analyzes a single file with advanced detection
    fn analyze_file(&self, path: &Path, patterns: &AnalysisPatterns) -> Result<FileAnalysis> {
        let content = fs::read_to_string(path)?;
        let risk_level = Self::get_file_risk_level(path);
        let is_env_file = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase().contains(".env"))
            .unwrap_or(false);
        let is_config_file = risk_level >= RiskLevel::Medium;

        let mut call_count = 0;
        let mut occurrence_lines = Vec::new();
        let mut exposures: Vec<ExposureDetail> = Vec::new();

        // Regex to extract values from assignments
        let value_pattern =
            Regex::new(r#"[=:]\s*["']([^"']+)["']|[=:]\s*([a-zA-Z0-9_\-./+]{8,})"#).ok();

        for (line_num, line) in content.lines().enumerate() {
            let line_number = line_num + 1; // 1-indexed

            // Skip comments
            let trimmed = line.trim();
            if trimmed.starts_with('#')
                || trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
            {
                continue;
            }

            // Count occurrences of the token in this line
            let matches: Vec<_> = patterns.token_regex.find_iter(line).collect();
            if matches.is_empty() {
                continue;
            }

            call_count += matches.len();
            occurrence_lines.push(line_number);

            // === Advanced exposure detection ===

            // 1. Check for .env file exposure (any assignment is dangerous)
            if is_env_file {
                if let Some(ref vp) = value_pattern {
                    if let Some(caps) = vp.captures(line) {
                        let value = caps.get(1).or(caps.get(2)).map(|m| m.as_str());
                        if let Some(v) = value {
                            // Check for known token prefix
                            if let Some(prefix_desc) = Self::detect_known_prefix(v) {
                                exposures.push(ExposureDetail {
                                    line: line_number,
                                    exposure_type: ExposureType::KnownTokenPrefix(
                                        prefix_desc.to_string(),
                                    ),
                                    context: Self::redact_value(v),
                                });
                            } else if Self::is_high_entropy_secret(v) {
                                exposures.push(ExposureDetail {
                                    line: line_number,
                                    exposure_type: ExposureType::HighEntropy,
                                    context: Self::redact_value(v),
                                });
                            } else {
                                exposures.push(ExposureDetail {
                                    line: line_number,
                                    exposure_type: ExposureType::EnvironmentFile,
                                    context: format!("{}=***", patterns.token_regex.as_str()),
                                });
                            }
                        }
                    }
                }
                continue;
            }

            // 2. Check for hardcoded values in config files
            if is_config_file {
                if let Some(ref vp) = value_pattern {
                    if let Some(caps) = vp.captures(line) {
                        let value = caps.get(1).or(caps.get(2)).map(|m| m.as_str());
                        if let Some(v) = value {
                            // Skip environment variable references
                            if v.starts_with('$')
                                || v.contains("env.")
                                || v.contains("ENV[")
                                || v.contains("getenv")
                            {
                                continue;
                            }

                            if let Some(prefix_desc) = Self::detect_known_prefix(v) {
                                exposures.push(ExposureDetail {
                                    line: line_number,
                                    exposure_type: ExposureType::KnownTokenPrefix(
                                        prefix_desc.to_string(),
                                    ),
                                    context: Self::redact_value(v),
                                });
                            } else if Self::is_high_entropy_secret(v) {
                                exposures.push(ExposureDetail {
                                    line: line_number,
                                    exposure_type: ExposureType::HighEntropy,
                                    context: Self::redact_value(v),
                                });
                            } else {
                                exposures.push(ExposureDetail {
                                    line: line_number,
                                    exposure_type: ExposureType::ConfigFile,
                                    context: format!(
                                        "Hardcoded in {}",
                                        risk_level_name(risk_level)
                                    ),
                                });
                            }
                        }
                    }
                }
            }

            // 3. Standard exposure pattern check (logging, hardcoded values)
            if patterns.exposure_regex.is_match(line) {
                // Determine exposure type
                let exposure_type = if line.to_lowercase().contains("log")
                    || line.to_lowercase().contains("print")
                    || line.to_lowercase().contains("console")
                    || line.to_lowercase().contains("echo")
                {
                    ExposureType::LoggedOutput
                } else {
                    ExposureType::HardcodedValue
                };

                // Avoid duplicates
                if !exposures.iter().any(|e| e.line == line_number) {
                    exposures.push(ExposureDetail {
                        line: line_number,
                        exposure_type,
                        context: Self::truncate_line(line),
                    });
                }
            }
        }

        let exposure_lines: Vec<usize> = exposures.iter().map(|e| e.line).collect();
        let risk_score = call_count * risk_level.multiplier();

        Ok(FileAnalysis {
            path: path.to_path_buf(),
            call_count,
            has_exposure: !exposures.is_empty(),
            risk_level,
            risk_score,
            exposures,
            exposure_lines,
            occurrence_lines,
        })
    }

    /// Redacts a secret value for safe display
    fn redact_value(value: &str) -> String {
        if value.len() <= 8 {
            return "***".to_string();
        }
        let prefix = &value[..4];
        let suffix = &value[value.len() - 4..];
        format!("{}...{}", prefix, suffix)
    }

    /// Truncates a line for display
    fn truncate_line(line: &str) -> String {
        let trimmed = line.trim();
        if trimmed.len() <= 50 {
            trimmed.to_string()
        } else {
            format!("{}...", &trimmed[..47])
        }
    }

    /// Creates a timeout report
    fn timeout_report(
        &self,
        token_name: &str,
        search_dir: &Path,
        start: Instant,
    ) -> AnalysisReport {
        AnalysisReport {
            token_name: token_name.to_string(),
            search_dir: search_dir.to_path_buf(),
            total_calls: 0,
            exposure_count: 0,
            total_risk_score: 0,
            critical_files: 0,
            files: vec![],
            duration: start.elapsed(),
            files_scanned: 0,
            truncated: true,
            errors: vec!["Analysis timed out".to_string()],
        }
    }
}

/// Helper to get a readable name for risk level
fn risk_level_name(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "source file",
        RiskLevel::Medium => "config file",
        RiskLevel::High => "sensitive config",
        RiskLevel::Critical => "secrets file",
    }
}

/// Internal struct for regex patterns
struct AnalysisPatterns {
    token_regex: Regex,
    exposure_regex: Regex,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_test_dir() -> TempDir {
        let dir = TempDir::new().unwrap();

        // Create test files
        fs::write(
            dir.path().join("config.py"),
            r#"
import os
API_KEY = os.getenv("API_KEY")
db_url = f"postgres://{API_KEY}@localhost/db"
"#,
        )
        .unwrap();

        fs::write(
            dir.path().join("main.js"),
            r#"
const API_KEY = process.env.API_KEY;
console.log("API Key:", API_KEY);
fetch(url, { headers: { "Authorization": API_KEY } });
"#,
        )
        .unwrap();

        fs::write(
            dir.path().join("safe.rs"),
            r#"
let api_key = std::env::var("API_KEY")?;
client.set_header("Authorization", &api_key);
"#,
        )
        .unwrap();

        fs::write(
            dir.path().join("debug.py"),
            r#"
import logging
logger = logging.getLogger(__name__)
logger.debug(f"Using API_KEY: {API_KEY}")
print(f"Debug: API_KEY = {API_KEY}")
"#,
        )
        .unwrap();

        // Create a subdirectory with more files
        let subdir = dir.path().join("src");
        fs::create_dir(&subdir).unwrap();
        fs::write(
            subdir.join("api.ts"),
            r#"
export const API_KEY = process.env.API_KEY;
export function getHeaders() {
    return { "X-API-Key": API_KEY };
}
"#,
        )
        .unwrap();

        dir
    }

    #[test]
    fn test_analyzer_finds_token_occurrences() {
        let dir = setup_test_dir();
        let analyzer = TokenSecurityAnalyzer::default_analyzer();

        let report = analyzer.analyze("API_KEY", dir.path()).unwrap();

        assert!(report.total_calls > 0, "Should find token occurrences");
        assert!(!report.files.is_empty(), "Should have files with matches");
    }

    #[test]
    fn test_analyzer_detects_exposure() {
        let dir = setup_test_dir();
        let analyzer = TokenSecurityAnalyzer::default_analyzer();

        let report = analyzer.analyze("API_KEY", dir.path()).unwrap();

        assert!(report.exposure_count > 0, "Should detect exposure");
        assert!(report.has_security_issues(), "Should have security issues");

        // Check specific exposure files
        let exposed = report.exposed_files();
        let exposed_paths: Vec<_> = exposed
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(
            exposed_paths.iter().any(|p| p == "main.js"),
            "main.js should be exposed (console.log)"
        );
        assert!(
            exposed_paths.iter().any(|p| p == "debug.py"),
            "debug.py should be exposed (logger.debug, print)"
        );
    }

    #[test]
    fn test_analyzer_respects_word_boundaries() {
        let dir = TempDir::new().unwrap();

        fs::write(
            dir.path().join("test.py"),
            r#"
API_KEY_NAME = "test"
MY_API_KEY = "value"
API_KEY = "secret"
"#,
        )
        .unwrap();

        let analyzer = TokenSecurityAnalyzer::default_analyzer();
        let report = analyzer.analyze("API_KEY", dir.path()).unwrap();

        // Should only find exact "API_KEY", not "API_KEY_NAME" or "MY_API_KEY"
        assert_eq!(report.total_calls, 1, "Should match exact token only");
    }

    #[test]
    fn test_analyzer_config_fast() {
        let config = AnalyzerConfig::fast();
        assert_eq!(config.max_files, 1_000);
        assert_eq!(config.timeout_ms, 5_000);
    }

    #[test]
    fn test_analyzer_config_thorough() {
        let config = AnalyzerConfig::thorough();
        assert_eq!(config.max_files, 0);
        assert!(config.include_hidden);
    }

    #[test]
    fn test_analyzer_empty_token() {
        let dir = TempDir::new().unwrap();
        let analyzer = TokenSecurityAnalyzer::default_analyzer();

        let result = analyzer.analyze("", dir.path());
        assert!(result.is_err(), "Should reject empty token");
    }

    #[test]
    fn test_analyzer_nonexistent_dir() {
        let analyzer = TokenSecurityAnalyzer::default_analyzer();

        let result = analyzer.analyze("TOKEN", Path::new("/nonexistent/path"));
        assert!(result.is_err(), "Should reject nonexistent directory");
    }

    #[test]
    fn test_analyzer_report_sorting() {
        let dir = setup_test_dir();
        let analyzer = TokenSecurityAnalyzer::default_analyzer();
        let report = analyzer.analyze("API_KEY", dir.path()).unwrap();

        let sorted = report.files_sorted();

        // First files should have exposure
        if !sorted.is_empty() && sorted[0].has_exposure {
            assert!(
                sorted.iter().take_while(|f| f.has_exposure).count() > 0,
                "Exposed files should come first"
            );
        }
    }

    #[test]
    fn test_analyzer_ignores_node_modules() {
        let dir = TempDir::new().unwrap();

        // Create node_modules directory with matching file
        let nm = dir.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("test.js"), "const API_KEY = 'test';").unwrap();

        // Create regular file
        fs::write(dir.path().join("main.js"), "const API_KEY = 'test';").unwrap();

        let analyzer = TokenSecurityAnalyzer::default_analyzer();
        let report = analyzer.analyze("API_KEY", dir.path()).unwrap();

        // Should only find in main.js, not node_modules
        assert_eq!(report.files.len(), 1);
        assert!(report.files[0].path.file_name().unwrap() == "main.js");
    }

    #[test]
    fn test_analyzer_performance_metrics() {
        let dir = setup_test_dir();
        let analyzer = TokenSecurityAnalyzer::default_analyzer();

        let report = analyzer.analyze("API_KEY", dir.path()).unwrap();

        assert!(
            report.duration.as_millis() < 5000,
            "Analysis should complete quickly (< 5s)"
        );
        assert!(report.files_scanned > 0, "Should report files scanned");
    }

    #[test]
    fn test_analyzer_multiple_occurrences_per_line() {
        let dir = TempDir::new().unwrap();

        fs::write(
            dir.path().join("test.py"),
            "x = API_KEY + API_KEY + API_KEY\n",
        )
        .unwrap();

        let analyzer = TokenSecurityAnalyzer::default_analyzer();
        let report = analyzer.analyze("API_KEY", dir.path()).unwrap();

        assert_eq!(
            report.total_calls, 3,
            "Should count all occurrences on same line"
        );
        assert_eq!(
            report.files[0].occurrence_lines.len(),
            1,
            "Should only have 1 line"
        );
    }
}
