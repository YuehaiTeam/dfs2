pub mod analyzer;
pub mod formatters;
pub mod models;
pub mod parser;
pub mod stats;

use clap::Args;
use std::path::Path;

#[derive(Args)]
pub struct AnalyzeArgs {
    /// Log file path to analyze
    pub log_file: String,

    /// Output format: text or json
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Output path, use "-" for stdout
    #[arg(short = 'o', long)]
    pub output: Option<String>,
}

/// Main entry point for analyze command
pub async fn handle_analyze(args: AnalyzeArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Validate input file exists
    if !Path::new(&args.log_file).exists() {
        return Err(format!("Log file not found: {}", args.log_file).into());
    }

    // Validate output format
    if args.format != "text" && args.format != "json" {
        return Err("Format must be 'text' or 'json'".into());
    }

    eprintln!("Analyzing log file: {}", args.log_file);

    // Parse log file
    let sessions = parser::parse_log_file(&args.log_file)
        .await
        .map_err(|e| format!("Failed to parse log file: {}", e))?;
    eprintln!("Parsed {} session records", sessions.len());

    // Analyze sessions
    let mut analysis_result = analyzer::analyze_sessions(sessions)?;

    // Update log file info
    analyzer::update_log_file_info(&mut analysis_result, &args.log_file);

    // Format output
    let output_content = match args.format.as_str() {
        "json" => formatters::json::format_json(&analysis_result)?,
        "text" => formatters::text::format_text(&analysis_result),
        _ => unreachable!(),
    };

    // Write output
    write_output(&output_content, args.output.as_deref())?;

    Ok(())
}

/// Write output to stdout or file
fn write_output(
    content: &str,
    output_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match output_path {
        None | Some("-") => {
            // Output to stdout
            println!("{}", content);
        }
        Some(path) => {
            // Output to file
            std::fs::write(path, content)?;
            eprintln!("Analysis report written to: {}", path);
        }
    }
    Ok(())
}
