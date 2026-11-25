//! Captured-process diagnostics for cryptography 50.0.0 on native Windows ARM64.
//!
//! Compile with: rustc --edition=2021 arm64_stdio_probe.rs -o arm64_stdio_probe.exe
//! This harness does not repair handles, change Python buffering, or install
//! packages. Its parent workflow must impose a time limit on the whole process.

use std::env;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const MAX_ITERATIONS: usize = 10;
const MAX_RAW_STREAM_BYTES: usize = 16 * 1024;
const MAX_JSON_STREAM_BYTES: usize = 24 * 1024;
const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
const CONTROL: &str = "import platform; print(platform.python_implementation(), end='')";
const BASELINE: &str = "import os; import setuptools.dist; \
import setuptools.command.build_ext; \
b = setuptools.command.build_ext.build_ext(setuptools.dist.Distribution()); \
b.finalize_options(); print(os.pathsep.join(b.include_dirs), end='')";

struct Options {
    python: PathBuf,
    probe_script: PathBuf,
    output: PathBuf,
    package_path: Option<PathBuf>,
    iterations: usize,
}

fn parse_options() -> Result<Option<Options>, &'static str> {
    let mut args = env::args_os().skip(1);
    let mut python = None;
    let mut probe_script = None;
    let mut output = None;
    let mut package_path = None;
    let mut iterations = 3;
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            return Ok(None);
        }
        let value: OsString = args.next().ok_or("missing option value")?;
        match flag.to_str() {
            Some("--python") if python.is_none() => python = Some(PathBuf::from(value)),
            Some("--probe-script") if probe_script.is_none() => {
                probe_script = Some(PathBuf::from(value))
            }
            Some("--output") if output.is_none() => output = Some(PathBuf::from(value)),
            Some("--package-path") if package_path.is_none() => {
                package_path = Some(PathBuf::from(value))
            }
            Some("--iterations") => {
                iterations = value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .filter(|value| (1..=MAX_ITERATIONS).contains(value))
                    .ok_or("iterations must be an integer from 1 through 10")?;
            }
            _ => return Err("unknown or repeated option"),
        }
    }
    let options = Options {
        python: python.ok_or("--python is required")?,
        probe_script: probe_script.ok_or("--probe-script is required")?,
        output: output.ok_or("--output is required")?,
        package_path,
        iterations,
    };
    if !options.python.is_absolute() || !options.python.is_file() {
        return Err("--python must name an existing absolute interpreter path");
    }
    if !options.probe_script.is_absolute() || !options.probe_script.is_file() {
        return Err("--probe-script must name an existing absolute script path");
    }
    if let Some(path) = &options.package_path {
        if !path.is_absolute() || !path.is_dir() {
            return Err("--package-path must name an existing absolute directory");
        }
    }
    Ok(Some(options))
}

fn json_char(value: char) -> String {
    match value {
        '"' => "\\\"".to_owned(),
        '\\' => "\\\\".to_owned(),
        '\n' => "\\n".to_owned(),
        '\r' => "\\r".to_owned(),
        '\t' => "\\t".to_owned(),
        '\u{08}' => "\\b".to_owned(),
        '\u{0c}' => "\\f".to_owned(),
        value if value < '\u{20}' => format!("\\u{:04x}", u32::from(value)),
        value => value.to_string(),
    }
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for value in value.chars() {
        output.push_str(&json_char(value));
    }
    output.push('"');
    output
}

struct Capture {
    json: String,
    original_bytes: usize,
    truncated: bool,
    utf8_valid: bool,
}

fn capture(bytes: &[u8]) -> Capture {
    let prefix = &bytes[..bytes.len().min(MAX_RAW_STREAM_BYTES)];
    let decoded = String::from_utf8_lossy(prefix);
    let mut json = String::from("\"");
    let mut truncated = prefix.len() < bytes.len();
    for character in decoded.chars() {
        let escaped = json_char(character);
        if json.len() + escaped.len() + 1 > MAX_JSON_STREAM_BYTES {
            truncated = true;
            break;
        }
        json.push_str(&escaped);
    }
    json.push('"');
    Capture {
        json,
        original_bytes: bytes.len(),
        truncated,
        utf8_valid: std::str::from_utf8(bytes).is_ok(),
    }
}

struct Report {
    file: File,
    bytes_written: usize,
}

impl Report {
    fn create(path: &Path) -> io::Result<Self> {
        // Evidence is never overwritten; use a distinct output per invocation.
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        Ok(Self {
            file,
            bytes_written: 0,
        })
    }

    fn write(&mut self, record: &str) -> io::Result<()> {
        if self.bytes_written + record.len() + 1 > MAX_REPORT_BYTES {
            return Err(io::Error::other("diagnostic report size budget exceeded"));
        }
        self.file.write_all(record.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.bytes_written += record.len() + 1;
        Ok(())
    }
}

fn optional_number(value: Option<i32>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

fn run(options: &Options) -> io::Result<bool> {
    let mut report = Report::create(&options.output)?;
    report.write(&format!(
        "{{\"record\":\"session\",\"schema_version\":1,\"iterations\":{},\
\"max_iterations\":{},\"max_raw_stream_bytes\":{},\"max_report_bytes\":{},\
\"python_path_label\":\"explicit_interpreter\",\
\"package_path_override\":{},\"buffering_policy\":\"inherited_no_u_flag\",\
\"child_pythonioencoding\":\"utf-8\",\
\"capture_method\":\"std::process::Command.output\",\
\"probe_order\":[\"cpython_control\",\"setuptools_includes_exact\",\
\"setuptools_includes_instrumented\"]}}",
        options.iterations,
        MAX_ITERATIONS,
        MAX_RAW_STREAM_BYTES,
        MAX_REPORT_BYTES,
        options.package_path.is_some()
    ))?;

    let mut sequence = 0;
    let mut failed = 0;
    let mut truncated_streams = 0;
    let mut invalid_utf8_streams = 0;
    let mut output_mismatches = 0;
    let mut instrumented_without_baseline = 0;
    let mut spawn_errors = 0;
    for iteration in 1..=options.iterations {
        let mut baseline_stdout: Option<Vec<u8>> = None;
        for probe in [
            "cpython_control",
            "setuptools_includes_exact",
            "setuptools_includes_instrumented",
        ] {
            sequence += 1;
            let mut command = Command::new(&options.python);
            command
                .env("PYTHONIOENCODING", "utf-8")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // The default venv comparison leaves PYTHONPATH untouched.
            // Only the explicitly requested base-interpreter comparison uses
            // the same diagnostic packages through this child-only override.
            if let Some(package_path) = &options.package_path {
                command.env("PYTHONPATH", package_path);
            }
            match probe {
                "cpython_control" => {
                    command.arg("-c").arg(CONTROL);
                }
                "setuptools_includes_exact" => {
                    command.arg("-c").arg(BASELINE);
                }
                _ => {
                    command.arg(&options.probe_script);
                }
            }

            // Match the upstream captured-process path. The controlled child
            // scripts are small; serialization is additionally bounded below.
            // Process time is bounded by the enclosing workflow timeout.
            match command.output() {
                Ok(child) => {
                    let stdout = capture(&child.stdout);
                    let stderr = capture(&child.stderr);
                    truncated_streams += usize::from(stdout.truncated);
                    truncated_streams += usize::from(stderr.truncated);
                    invalid_utf8_streams += usize::from(!stdout.utf8_valid);
                    invalid_utf8_streams += usize::from(!stderr.utf8_valid);

                    let include_output_valid = child.status.success()
                        && !child.stdout.is_empty()
                        && stdout.utf8_valid
                        && !stdout.truncated;
                    if probe == "setuptools_includes_exact" && include_output_valid {
                        baseline_stdout = Some(child.stdout.clone());
                    }
                    let output_matches_baseline =
                        if probe == "setuptools_includes_instrumented" {
                            let matches = baseline_stdout.as_ref().map(|expected| {
                                child.stdout.as_slice() == expected.as_slice()
                            });
                            if matches == Some(false) {
                                output_mismatches += 1;
                            } else if matches.is_none() {
                                instrumented_without_baseline += 1;
                            }
                            matches
                        } else {
                            None
                        };
                    let passed = match probe {
                        "cpython_control" => {
                            child.status.success()
                                && child.stdout == b"CPython"
                                && child.stderr.is_empty()
                        }
                        "setuptools_includes_exact" => include_output_valid,
                        _ => include_output_valid && output_matches_baseline == Some(true),
                    };
                    if !passed {
                        failed += 1;
                    }
                    report.write(&format!(
                        "{{\"record\":\"child\",\"sequence\":{},\"iteration\":{},\
\"probe\":{},\"package_path_override\":{},\"exit_code\":{},\
\"exit_success\":{},\"probe_passed\":{},\
\"output_matches_baseline\":{},\
\"stdout_bytes\":{},\"stdout_truncated\":{},\"stdout_utf8_valid\":{},\
\"stderr_bytes\":{},\"stderr_truncated\":{},\"stderr_utf8_valid\":{},\
\"stdout\":{},\"stderr\":{}}}",
                        sequence,
                        iteration,
                        json_string(probe),
                        options.package_path.is_some(),
                        optional_number(child.status.code()),
                        child.status.success(),
                        passed,
                        optional_bool(output_matches_baseline),
                        stdout.original_bytes,
                        stdout.truncated,
                        stdout.utf8_valid,
                        stderr.original_bytes,
                        stderr.truncated,
                        stderr.utf8_valid,
                        stdout.json,
                        stderr.json
                    ))?;
                }
                Err(error) => {
                    failed += 1;
                    spawn_errors += 1;
                    report.write(&format!(
                        "{{\"record\":\"child_spawn_error\",\"sequence\":{},\
\"iteration\":{},\"probe\":{},\"output_matches_baseline\":null,\
\"error_kind\":{},\"os_error\":{}}}",
                        sequence,
                        iteration,
                        json_string(probe),
                        json_string(&format!("{:?}", error.kind())),
                        optional_number(error.raw_os_error())
                    ))?;
                }
            }
        }
    }
    let success = failed == 0
        && truncated_streams == 0
        && invalid_utf8_streams == 0
        && output_mismatches == 0;
    report.write(&format!(
        "{{\"record\":\"summary\",\"children_attempted\":{},\
\"failed_children\":{},\"spawn_errors\":{},\"truncated_streams\":{},\
\"invalid_utf8_streams\":{},\"output_mismatches\":{},\
\"instrumented_without_baseline\":{},\
\"success\":{}}}",
        sequence,
        failed,
        spawn_errors,
        truncated_streams,
        invalid_utf8_streams,
        output_mismatches,
        instrumented_without_baseline,
        success
    ))?;
    Ok(success)
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!(
                "Usage: arm64_stdio_probe --python ABSOLUTE_PYTHON \
--probe-script ABSOLUTE_SCRIPT --output NEW_REPORT.jsonl \
[--iterations 3] [--package-path ABSOLUTE_SITE_PACKAGES]"
            );
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("diagnostic configuration error: {message}");
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            // Deliberately omit error text, which can contain local paths.
            eprintln!(
                "diagnostic report error: kind={:?} os_error={:?}",
                error.kind(),
                error.raw_os_error()
            );
            ExitCode::from(2)
        }
    }
}
