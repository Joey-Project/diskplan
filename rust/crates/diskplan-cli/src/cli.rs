use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::batch::{BatchOptions, BatchProfile, PlanningAgentMode};

pub const USAGE: &str = "usage: diskplan [--profile standard|full-audit] [--agent-mode off|ask|auto] [diskplan-engine]\n       diskplan --handshake [diskplan-engine]\n       diskplan --batch --profile standard|full-audit --dry-run --no-history --no-audit-file [--agent-mode off|ask|auto] --root <absolute-path>";
const MAXIMUM_ROOT_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandLine {
    VersionJson,
    Handshake { engine: Option<PathBuf> },
    Interactive(InteractiveOptions),
    Batch(BatchOptions),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InteractiveOptions {
    pub engine: Option<PathBuf>,
    pub profile: BatchProfile,
    pub agent_mode: PlanningAgentMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageError {
    detail: &'static str,
}

impl UsageError {
    pub fn detail(&self) -> &'static str {
        self.detail
    }
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<CommandLine, UsageError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.iter().any(|argument| argument == "--batch") {
        return parse_batch(args);
    }

    match args.as_slice() {
        [] => Ok(CommandLine::Interactive(InteractiveOptions {
            engine: None,
            profile: BatchProfile::Standard,
            agent_mode: PlanningAgentMode::Ask,
        })),
        [flag] if flag == "--version-json" => Ok(CommandLine::VersionJson),
        [flag] if flag == "--handshake" => Ok(CommandLine::Handshake { engine: None }),
        [flag, engine] if flag == "--handshake" => Ok(CommandLine::Handshake {
            engine: Some(PathBuf::from(engine)),
        }),
        [engine] if !is_option(engine) => Ok(CommandLine::Interactive(InteractiveOptions {
            engine: Some(PathBuf::from(engine)),
            profile: BatchProfile::Standard,
            agent_mode: PlanningAgentMode::Ask,
        })),
        _ => parse_interactive(args),
    }
}

fn parse_interactive(args: Vec<OsString>) -> Result<CommandLine, UsageError> {
    let mut profile = BatchProfile::Standard;
    let mut profile_seen = false;
    let mut agent_mode = PlanningAgentMode::Ask;
    let mut agent_mode_seen = false;
    let mut engine = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_os_str() {
            value if value == "--profile" => {
                if profile_seen {
                    return Err(usage_error("duplicate --profile"));
                }
                profile_seen = true;
                index += 1;
                profile = parse_profile(
                    args.get(index)
                        .ok_or_else(|| usage_error("--profile needs a value"))?,
                )?;
            }
            value if value == "--agent-mode" => {
                if agent_mode_seen {
                    return Err(usage_error("duplicate --agent-mode"));
                }
                agent_mode_seen = true;
                index += 1;
                agent_mode = parse_agent_mode(
                    args.get(index)
                        .ok_or_else(|| usage_error("--agent-mode needs a value"))?,
                )?;
            }
            value if !is_option(value) && engine.is_none() => engine = Some(PathBuf::from(value)),
            _ => return Err(usage_error("unknown or incompatible arguments")),
        }
        index += 1;
    }
    Ok(CommandLine::Interactive(InteractiveOptions {
        engine,
        profile,
        agent_mode,
    }))
}

fn parse_batch(args: Vec<OsString>) -> Result<CommandLine, UsageError> {
    let mut batch = false;
    let mut profile = None;
    let mut dry_run = false;
    let mut no_history = false;
    let mut no_audit_file = false;
    let mut agent_mode = None;
    let mut root = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_os_str() {
            value if value == "--batch" => set_once(&mut batch, "duplicate --batch")?,
            value if value == "--dry-run" => set_once(&mut dry_run, "duplicate --dry-run")?,
            value if value == "--no-history" => {
                set_once(&mut no_history, "duplicate --no-history")?
            }
            value if value == "--no-audit-file" => {
                set_once(&mut no_audit_file, "duplicate --no-audit-file")?
            }
            value if value == "--profile" => {
                if profile.is_some() {
                    return Err(usage_error("duplicate --profile"));
                }
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| usage_error("--profile needs a value"))?;
                profile = Some(parse_profile(value)?);
            }
            value if value == "--agent-mode" => {
                if agent_mode.is_some() {
                    return Err(usage_error("duplicate --agent-mode"));
                }
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| usage_error("--agent-mode needs a value"))?;
                agent_mode = Some(parse_agent_mode(value)?);
            }
            value if value == "--root" => {
                if root.is_some() {
                    return Err(usage_error("duplicate --root"));
                }
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| usage_error("--root needs a value"))?;
                validate_root(value)?;
                root = Some(value.clone());
            }
            _ => return Err(usage_error("unknown or incompatible batch argument")),
        }
        index += 1;
    }

    if !(batch && dry_run && no_history && no_audit_file) {
        return Err(usage_error(
            "batch requires --dry-run --no-history --no-audit-file",
        ));
    }
    let profile = profile.ok_or_else(|| usage_error("batch requires --profile"))?;
    let root = root.ok_or_else(|| usage_error("batch requires exactly one --root"))?;

    Ok(CommandLine::Batch(BatchOptions {
        profile,
        root,
        agent_mode: agent_mode.unwrap_or_default(),
    }))
}

fn parse_profile(value: &OsStr) -> Result<BatchProfile, UsageError> {
    match value {
        value if value == "standard" => Ok(BatchProfile::Standard),
        value if value == "full-audit" => Ok(BatchProfile::FullAudit),
        _ => Err(usage_error("--profile must be standard or full-audit")),
    }
}

fn parse_agent_mode(value: &OsStr) -> Result<PlanningAgentMode, UsageError> {
    match value {
        value if value == "off" => Ok(PlanningAgentMode::Off),
        value if value == "ask" => Ok(PlanningAgentMode::Ask),
        value if value == "auto" => Ok(PlanningAgentMode::Auto),
        _ => Err(usage_error("--agent-mode must be off, ask, or auto")),
    }
}

fn set_once(value: &mut bool, duplicate: &'static str) -> Result<(), UsageError> {
    if *value {
        Err(usage_error(duplicate))
    } else {
        *value = true;
        Ok(())
    }
}

fn validate_root(root: &OsStr) -> Result<(), UsageError> {
    let bytes = root.as_bytes();
    if bytes.is_empty() || bytes.len() > MAXIMUM_ROOT_BYTES || !Path::new(root).is_absolute() {
        return Err(usage_error(
            "--root must be a bounded raw absolute filesystem path",
        ));
    }
    Ok(())
}

fn is_option(value: &OsStr) -> bool {
    value.as_bytes().first() == Some(&b'-')
}

const fn usage_error(detail: &'static str) -> UsageError {
    UsageError { detail }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn exact_batch(root: OsString) -> Vec<OsString> {
        [
            OsString::from("--batch"),
            OsString::from("--profile"),
            OsString::from("full-audit"),
            OsString::from("--dry-run"),
            OsString::from("--no-history"),
            OsString::from("--no-audit-file"),
            OsString::from("--root"),
            root,
        ]
        .into()
    }

    #[test]
    fn exact_batch_shape_preserves_raw_root_bytes() {
        let root = OsString::from_vec(b"/tmp/non-utf8-\xff".to_vec());
        let parsed = parse(exact_batch(root.clone())).expect("valid batch arguments");
        assert_eq!(
            parsed,
            CommandLine::Batch(BatchOptions {
                profile: BatchProfile::FullAudit,
                root,
                agent_mode: PlanningAgentMode::Ask,
            })
        );
    }

    #[test]
    fn batch_flags_are_order_independent_but_exactly_once() {
        let parsed = parse([
            OsString::from("--root"),
            OsString::from("/"),
            OsString::from("--no-audit-file"),
            OsString::from("--batch"),
            OsString::from("--dry-run"),
            OsString::from("--profile"),
            OsString::from("full-audit"),
            OsString::from("--no-history"),
        ]);
        assert!(matches!(parsed, Ok(CommandLine::Batch(_))));

        let mut duplicate = exact_batch(OsString::from("/"));
        duplicate.push(OsString::from("--dry-run"));
        assert_eq!(
            parse(duplicate).unwrap_err().detail(),
            "duplicate --dry-run"
        );
    }

    #[test]
    fn batch_agent_mode_supports_all_three_modes_and_defaults_to_ask() {
        for (name, expected) in [
            ("off", PlanningAgentMode::Off),
            ("ask", PlanningAgentMode::Ask),
            ("auto", PlanningAgentMode::Auto),
        ] {
            let mut arguments = exact_batch(OsString::from("/"));
            arguments.extend([OsString::from("--agent-mode"), OsString::from(name)]);
            let CommandLine::Batch(options) = parse(arguments).expect("valid agent mode") else {
                panic!("expected batch command");
            };
            assert_eq!(options.agent_mode, expected);
        }
        let CommandLine::Batch(options) =
            parse(exact_batch(OsString::from("/"))).expect("default agent mode")
        else {
            panic!("expected batch command");
        };
        assert_eq!(options.agent_mode, PlanningAgentMode::Ask);
    }

    #[test]
    fn incomplete_or_mutation_capable_batch_shapes_are_usage_errors() {
        for invalid in [
            vec![OsString::from("--batch")],
            vec![OsString::from("--batch"), OsString::from("--apply")],
            vec![
                OsString::from("--batch"),
                OsString::from("--profile"),
                OsString::from("quick"),
            ],
            exact_batch(OsString::from("relative")),
        ] {
            assert!(parse(invalid).is_err());
        }
    }

    #[test]
    fn legacy_modes_remain_narrow() {
        assert_eq!(
            parse([]),
            Ok(CommandLine::Interactive(InteractiveOptions {
                engine: None,
                profile: BatchProfile::Standard,
                agent_mode: PlanningAgentMode::Ask,
            }))
        );
        assert_eq!(
            parse([OsString::from("--handshake")]),
            Ok(CommandLine::Handshake { engine: None })
        );
        assert!(parse([OsString::from("--version-json"), OsString::from("x")]).is_err());
    }

    #[test]
    fn interactive_profile_and_agent_mode_are_configurable_with_safe_defaults() {
        assert_eq!(
            parse([
                OsString::from("--profile"),
                OsString::from("full-audit"),
                OsString::from("--agent-mode"),
                OsString::from("off"),
                OsString::from("/tmp/diskplan-engine"),
            ]),
            Ok(CommandLine::Interactive(InteractiveOptions {
                engine: Some(PathBuf::from("/tmp/diskplan-engine")),
                profile: BatchProfile::FullAudit,
                agent_mode: PlanningAgentMode::Off,
            }))
        );
    }
}
