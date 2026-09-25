//! What the command line asks for. A browser launch is recognised first, by
//! the caller it names; anything else is a person at a terminal or a
//! double-click.

use crate::ids::{Caller, ExtraIds, caller_from_args};

/// The help text.
pub const USAGE: &str = "\
warren-host: the Warren VPN browser extension's helper.

    warren-host                      install for this user (same as `install`)
    warren-host install [--extension-id ID]... [--gecko-id ID]...
                                     install for this user and register with every browser found
    warren-host uninstall            remove the helper and every browser registration
    warren-host status               show where the helper is registered
    warren-host --version            print the version and release channel

Browsers start it on their own; nothing else needs to run.
";

/// One parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// A browser started the helper for this extension.
    Host(Caller),
    /// Install for the current user. `interactive` when started with no
    /// argument at all (a double-click).
    Install {
        /// Extra extension ids to record.
        extra: ExtraIds,
        /// Started bare, by a person.
        interactive: bool,
    },
    /// Remove everything.
    Uninstall,
    /// Show the registrations.
    Status,
    /// Print the version.
    Version,
    /// Print the help.
    Help,
}

/// Parses the arguments after the program name.
///
/// # Errors
///
/// A message for the person who typed them.
pub fn parse(args: &[String]) -> Result<Invocation, String> {
    if let Some(caller) = caller_from_args(args) {
        return Ok(Invocation::Host(caller));
    }
    let Some((first, rest)) = args.split_first() else {
        return Ok(Invocation::Install {
            extra: ExtraIds::default(),
            interactive: true,
        });
    };
    let bare = |command: Invocation| {
        if rest.is_empty() {
            Ok(command)
        } else {
            Err(format!("{first} takes no argument"))
        }
    };
    match first.as_str() {
        "install" => parse_install(rest),
        "uninstall" => bare(Invocation::Uninstall),
        "status" => bare(Invocation::Status),
        "--version" | "-V" | "version" => bare(Invocation::Version),
        "--help" | "-h" | "help" => bare(Invocation::Help),
        other => Err(format!("{other} is not a command")),
    }
}

fn parse_install(args: &[String]) -> Result<Invocation, String> {
    let mut extra = ExtraIds::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let target = match flag.as_str() {
            "--extension-id" => &mut extra.extension_ids,
            "--gecko-id" => &mut extra.gecko_ids,
            other => return Err(format!("install does not take {other}")),
        };
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        target.push(value.clone());
    }
    Ok(Invocation::Install {
        extra,
        interactive: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn no_argument_is_an_interactive_install() {
        assert_eq!(
            parse(&[]),
            Ok(Invocation::Install {
                extra: ExtraIds::default(),
                interactive: true
            })
        );
    }

    #[test]
    fn install_records_repeated_ids() {
        let parsed = parse(&args(&[
            "install",
            "--extension-id",
            "abcdefghijklmnopabcdefghijklmnop",
            "--gecko-id",
            "a@b.c",
            "--extension-id",
            "ponmlkjihgfedcbaponmlkjihgfedcba",
        ]));
        assert_eq!(
            parsed,
            Ok(Invocation::Install {
                extra: ExtraIds {
                    extension_ids: args(&[
                        "abcdefghijklmnopabcdefghijklmnop",
                        "ponmlkjihgfedcbaponmlkjihgfedcba"
                    ]),
                    gecko_ids: args(&["a@b.c"]),
                },
                interactive: false,
            })
        );
    }

    #[test]
    fn a_browser_launch_wins_over_every_command() {
        assert!(matches!(
            parse(&args(&[
                "chrome-extension://dgkleicjbkfinjhhhmalipaepnlchfib/"
            ])),
            Ok(Invocation::Host(Caller::Chromium(_)))
        ));
        assert!(matches!(
            parse(&args(&[
                "C:\\x\\com.warrenbrowse.host.firefox.json",
                "vpn@warrenbrowse.com"
            ])),
            Ok(Invocation::Host(Caller::Firefox(_)))
        ));
    }

    #[test]
    fn parses_the_other_commands_and_refuses_the_unknown() {
        assert_eq!(parse(&args(&["uninstall"])), Ok(Invocation::Uninstall));
        assert_eq!(parse(&args(&["status"])), Ok(Invocation::Status));
        assert_eq!(parse(&args(&["--version"])), Ok(Invocation::Version));
        assert_eq!(parse(&args(&["--help"])), Ok(Invocation::Help));
        assert!(parse(&args(&["frobnicate"])).is_err());
        assert!(parse(&args(&["status", "now"])).is_err());
        assert!(parse(&args(&["install", "--extension-id"])).is_err());
        assert!(parse(&args(&["install", "--force"])).is_err());
    }
}
