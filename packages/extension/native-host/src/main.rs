//! `warren-host`: see the crate docs of [`warren_native_host`].

#![forbid(unsafe_code)]

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use warren_native_host::cli::{self, Invocation, USAGE};
use warren_native_host::engine::EngineBackend;
use warren_native_host::host::{self, HostExit};
use warren_native_host::ids::{Allowlist, BUILD_CHANNEL, Caller, ExtraIds};
use warren_native_host::install::{self, Platform};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    match cli::parse(&args) {
        Ok(Invocation::Host(caller)) => run_host(&caller),
        Ok(Invocation::Install { extra, interactive }) => {
            let code = run_install(&extra, interactive);
            if interactive && cfg!(windows) && std::io::stdin().is_terminal() {
                // A double-clicked console closes with the process: keep the
                // result on screen until it has been read.
                print!("Press Enter to close.");
                let _ = std::io::stdout().flush();
                let _ = std::io::stdin().lock().read_line(&mut String::new());
            }
            code
        }
        Ok(Invocation::Uninstall) => run_uninstall(),
        Ok(Invocation::Status) => run_status(),
        Ok(Invocation::Version) => {
            println!("{}", version_line());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("warren-host: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn version_line() -> String {
    format!(
        "warren-host {} ({} channel)",
        env!("CARGO_PKG_VERSION"),
        BUILD_CHANNEL.name()
    )
}

/// The directory of the running binary: the ids recorded at install time
/// live next to it.
fn own_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(PathBuf::from))
}

fn run_host(caller: &Caller) -> ExitCode {
    let extra = own_dir()
        .map(|dir| ExtraIds::load(&dir.join(ExtraIds::FILE_NAME)))
        .unwrap_or_default();
    if !Allowlist::new(BUILD_CHANNEL, &extra).admits(caller) {
        // stderr only: stdout belongs to the browser's framing.
        eprintln!("warren-host: this extension is not allowed to use the helper");
        return ExitCode::from(1);
    }
    let state_root = match Platform::current() {
        Ok(platform) => platform.state_dir(),
        Err(e) => {
            eprintln!("warren-host: {e}");
            return ExitCode::from(1);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("warren-host: cannot start the async runtime");
            return ExitCode::from(1);
        }
    };
    let exit = runtime.block_on(host::serve(
        EngineBackend::new(state_root),
        tokio::io::stdin(),
        tokio::io::stdout(),
        stop_signal(),
    ));
    // The stdin reader parks a blocking thread that only the process exit
    // releases; do not wait for it.
    runtime.shutdown_background();
    match exit {
        HostExit::EndOfStream | HostExit::Signalled => ExitCode::SUCCESS,
        HostExit::CorruptStream => {
            eprintln!("warren-host: corrupt message from the browser, tunnel torn down");
            ExitCode::from(1)
        }
    }
}

async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn run_install(extra: &ExtraIds, interactive: bool) -> ExitCode {
    let result = Platform::current().and_then(|platform| {
        let source = std::env::current_exe().map_err(|source| install::InstallError::Io {
            action: "locate",
            path: PathBuf::from("the running helper"),
            source,
        })?;
        install::install(&platform, &source, extra)
    });
    match result {
        Ok(report) => {
            if report.detected {
                println!(
                    "Warren helper installed for: {}. Go back to your browser, it is detected automatically.",
                    report.browsers.join(", ")
                );
            } else {
                println!(
                    "Warren helper installed. No browser was found yet, so it is registered for every supported browser: {}. Go back to your browser, it is detected automatically.",
                    report.browsers.join(", ")
                );
            }
            if !interactive {
                println!("Helper: {}", report.binary.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("warren-host: installation failed: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_uninstall() -> ExitCode {
    let platform = match Platform::current() {
        Ok(platform) => platform,
        Err(e) => {
            eprintln!("warren-host: {e}");
            return ExitCode::from(1);
        }
    };
    let report = install::uninstall(&platform);
    for path in &report.removed {
        println!("removed {}", path.display());
    }
    for path in &report.left {
        eprintln!(
            "could not remove {} (close every browser, then run uninstall again)",
            path.display()
        );
    }
    if report.left.is_empty() {
        println!("Warren helper uninstalled.");
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run_status() -> ExitCode {
    let platform = match Platform::current() {
        Ok(platform) => platform,
        Err(e) => {
            eprintln!("warren-host: {e}");
            return ExitCode::from(1);
        }
    };
    println!("{}", version_line());
    let binary = platform.binary_path();
    let installed = if binary.exists() {
        "installed"
    } else {
        "not installed"
    };
    println!("helper: {} ({installed})", binary.display());
    for (browser, registered) in install::registrations(&platform) {
        let mark = if registered { "registered" } else { "-" };
        println!("  {:<14} {mark}", browser.name);
    }
    ExitCode::SUCCESS
}
