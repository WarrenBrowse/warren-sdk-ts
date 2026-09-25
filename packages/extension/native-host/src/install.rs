//! Per-user installation, no administrator rights: the binary copies itself
//! into the user's data directory and registers the host manifest with every
//! browser it finds. Every path and manifest is computed by a pure function of
//! an injected [`Platform`], so the layout is tested on any machine.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::ids::{Allowlist, BUILD_CHANNEL, ExtraIds};
use crate::protocol::HOST_NAME;

/// The operating systems the helper ships for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// macOS.
    MacOs,
    /// Linux.
    Linux,
    /// Windows.
    Windows,
}

/// The user environment the layout derives from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    /// The operating system.
    pub os: Os,
    /// The user's home directory.
    pub home: PathBuf,
    /// `XDG_CONFIG_HOME` (Linux), when set.
    pub xdg_config_home: Option<PathBuf>,
    /// `XDG_DATA_HOME` (Linux), when set.
    pub xdg_data_home: Option<PathBuf>,
    /// `LOCALAPPDATA` (Windows), when set.
    pub local_app_data: Option<PathBuf>,
    /// `APPDATA` (Windows), when set.
    pub app_data: Option<PathBuf>,
}

/// Why installation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InstallError {
    /// No home directory could be determined.
    #[error("cannot find the home directory (HOME is not set)")]
    NoHome,
    /// A file operation failed.
    #[error("cannot {action} {path}")]
    Io {
        /// What was attempted.
        action: &'static str,
        /// The path it was attempted on.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The Windows registry refused a write.
    #[error("cannot register the helper under HKCU\\{0}")]
    Registry(String),
    /// An id given on the command line is malformed.
    #[error("{0} is not a valid extension id")]
    BadId(String),
}

fn io_err(action: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> InstallError {
    let path = path.to_path_buf();
    move |source| InstallError::Io {
        action,
        path,
        source,
    }
}

impl Platform {
    /// The platform this process runs on, read from its environment.
    ///
    /// # Errors
    ///
    /// [`InstallError::NoHome`] when no home directory is set.
    pub fn current() -> Result<Self, InstallError> {
        let var = |name: &str| {
            std::env::var_os(name)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let os = if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(windows) {
            Os::Windows
        } else {
            Os::Linux
        };
        let home = match os {
            Os::Windows => var("USERPROFILE").or_else(|| var("HOME")),
            _ => var("HOME"),
        }
        .ok_or(InstallError::NoHome)?;
        Ok(Self {
            os,
            home,
            xdg_config_home: var("XDG_CONFIG_HOME"),
            xdg_data_home: var("XDG_DATA_HOME"),
            local_app_data: var("LOCALAPPDATA"),
            app_data: var("APPDATA"),
        })
    }

    fn local_app_data(&self) -> PathBuf {
        self.local_app_data
            .clone()
            .unwrap_or_else(|| self.home.join("AppData").join("Local"))
    }

    fn app_data(&self) -> PathBuf {
        self.app_data
            .clone()
            .unwrap_or_else(|| self.home.join("AppData").join("Roaming"))
    }

    fn mac_support(&self) -> PathBuf {
        self.home.join("Library").join("Application Support")
    }

    fn xdg_config(&self) -> PathBuf {
        self.xdg_config_home
            .clone()
            .unwrap_or_else(|| self.home.join(".config"))
    }

    /// The per-user directory holding the binary, its id record, its state and
    /// (on Windows) its manifests.
    #[must_use]
    pub fn helper_dir(&self) -> PathBuf {
        match self.os {
            Os::MacOs => self.mac_support().join("Warren").join("Helper"),
            Os::Linux => self
                .xdg_data_home
                .clone()
                .unwrap_or_else(|| self.home.join(".local").join("share"))
                .join("warren")
                .join("helper"),
            Os::Windows => self.local_app_data().join("Warren").join("Helper"),
        }
    }

    /// Where the installed binary lives.
    #[must_use]
    pub fn binary_path(&self) -> PathBuf {
        let name = match self.os {
            Os::Windows => "warren-host.exe",
            _ => "warren-host",
        };
        self.helper_dir().join(name)
    }

    /// Where the engine keeps its anti-rollback floors.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.helper_dir().join("state")
    }

    /// Where the ids recorded at install time are kept.
    #[must_use]
    pub fn extra_ids_path(&self) -> PathBuf {
        self.helper_dir().join(ExtraIds::FILE_NAME)
    }

    /// On Windows the manifests are files next to the binary that the
    /// registry points at.
    #[must_use]
    pub fn windows_manifest_path(&self, family: Family) -> PathBuf {
        let suffix = match family {
            Family::Chromium => "chromium",
            Family::Firefox => "firefox",
        };
        self.helper_dir().join(format!("{HOST_NAME}.{suffix}.json"))
    }
}

/// Browser families, which differ in the manifest's caller field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// `allowed_origins`.
    Chromium,
    /// `allowed_extensions`.
    Firefox,
}

/// How a browser finds the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// A manifest file in this directory.
    Directory(PathBuf),
    /// A registry key under `HKCU` whose default value is the manifest path.
    RegistryKey(String),
}

/// One browser the helper registers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Browser {
    /// Display name.
    pub name: &'static str,
    /// Manifest family.
    pub family: Family,
    /// A directory whose presence says the browser has been used here.
    pub profile: PathBuf,
    /// Where it looks for the manifest.
    pub registration: Registration,
}

impl Browser {
    /// The manifest file this browser reads, wherever it lives.
    #[must_use]
    pub fn manifest_file(&self, platform: &Platform) -> PathBuf {
        match &self.registration {
            Registration::Directory(dir) => dir.join(format!("{HOST_NAME}.json")),
            Registration::RegistryKey(_) => platform.windows_manifest_path(self.family),
        }
    }
}

/// Every browser the helper knows on `platform`.
#[must_use]
pub fn browsers(platform: &Platform) -> Vec<Browser> {
    use Family::{Chromium, Firefox};
    match platform.os {
        Os::MacOs => {
            let support = platform.mac_support();
            let dir = |name: &'static str, family: Family, profile: &str, data: &str| Browser {
                name,
                family,
                profile: support.join(profile),
                registration: Registration::Directory(
                    support.join(data).join("NativeMessagingHosts"),
                ),
            };
            vec![
                dir("Chrome", Chromium, "Google/Chrome", "Google/Chrome"),
                dir(
                    "Chrome Beta",
                    Chromium,
                    "Google/Chrome Beta",
                    "Google/Chrome Beta",
                ),
                dir(
                    "Chrome Dev",
                    Chromium,
                    "Google/Chrome Dev",
                    "Google/Chrome Dev",
                ),
                dir(
                    "Chrome Canary",
                    Chromium,
                    "Google/Chrome Canary",
                    "Google/Chrome Canary",
                ),
                dir("Chromium", Chromium, "Chromium", "Chromium"),
                dir(
                    "Brave",
                    Chromium,
                    "BraveSoftware/Brave-Browser",
                    "BraveSoftware/Brave-Browser",
                ),
                dir(
                    "Brave Beta",
                    Chromium,
                    "BraveSoftware/Brave-Browser-Beta",
                    "BraveSoftware/Brave-Browser-Beta",
                ),
                dir(
                    "Brave Nightly",
                    Chromium,
                    "BraveSoftware/Brave-Browser-Nightly",
                    "BraveSoftware/Brave-Browser-Nightly",
                ),
                dir("Edge", Chromium, "Microsoft Edge", "Microsoft Edge"),
                dir(
                    "Edge Beta",
                    Chromium,
                    "Microsoft Edge Beta",
                    "Microsoft Edge Beta",
                ),
                dir(
                    "Edge Dev",
                    Chromium,
                    "Microsoft Edge Dev",
                    "Microsoft Edge Dev",
                ),
                dir(
                    "Edge Canary",
                    Chromium,
                    "Microsoft Edge Canary",
                    "Microsoft Edge Canary",
                ),
                dir("Vivaldi", Chromium, "Vivaldi", "Vivaldi"),
                dir("Arc", Chromium, "Arc/User Data", "Arc/User Data"),
                dir(
                    "Opera",
                    Chromium,
                    "com.operasoftware.Opera",
                    "com.operasoftware.Opera",
                ),
                dir("Firefox", Firefox, "Firefox", "Mozilla"),
                dir("LibreWolf", Firefox, "librewolf", "LibreWolf"),
            ]
        }
        Os::Linux => {
            let config = platform.xdg_config();
            let chromium = |name: &'static str, dir: &str| Browser {
                name,
                family: Chromium,
                profile: config.join(dir),
                registration: Registration::Directory(
                    config.join(dir).join("NativeMessagingHosts"),
                ),
            };
            let home = &platform.home;
            vec![
                chromium("Chrome", "google-chrome"),
                chromium("Chrome Beta", "google-chrome-beta"),
                chromium("Chrome Dev", "google-chrome-unstable"),
                chromium("Chromium", "chromium"),
                chromium("Brave", "BraveSoftware/Brave-Browser"),
                chromium("Brave Beta", "BraveSoftware/Brave-Browser-Beta"),
                chromium("Brave Nightly", "BraveSoftware/Brave-Browser-Nightly"),
                chromium("Edge", "microsoft-edge"),
                chromium("Edge Beta", "microsoft-edge-beta"),
                chromium("Edge Dev", "microsoft-edge-dev"),
                chromium("Vivaldi", "vivaldi"),
                chromium("Opera", "opera"),
                Browser {
                    name: "Firefox",
                    family: Firefox,
                    profile: home.join(".mozilla/firefox"),
                    registration: Registration::Directory(
                        home.join(".mozilla/native-messaging-hosts"),
                    ),
                },
                Browser {
                    name: "LibreWolf",
                    family: Firefox,
                    profile: home.join(".librewolf"),
                    registration: Registration::Directory(
                        home.join(".librewolf/native-messaging-hosts"),
                    ),
                },
            ]
        }
        Os::Windows => {
            let local = platform.local_app_data();
            let roaming = platform.app_data();
            let key =
                |vendor: &str| format!("Software\\{vendor}\\NativeMessagingHosts\\{HOST_NAME}");
            vec![
                Browser {
                    name: "Chrome",
                    family: Chromium,
                    profile: local.join("Google").join("Chrome"),
                    registration: Registration::RegistryKey(key("Google\\Chrome")),
                },
                Browser {
                    name: "Chromium",
                    family: Chromium,
                    profile: local.join("Chromium"),
                    registration: Registration::RegistryKey(key("Chromium")),
                },
                Browser {
                    name: "Edge",
                    family: Chromium,
                    profile: local.join("Microsoft").join("Edge"),
                    registration: Registration::RegistryKey(key("Microsoft\\Edge")),
                },
                Browser {
                    name: "Brave",
                    family: Chromium,
                    profile: local.join("BraveSoftware").join("Brave-Browser"),
                    registration: Registration::RegistryKey(key("BraveSoftware\\Brave-Browser")),
                },
                Browser {
                    name: "Vivaldi",
                    family: Chromium,
                    profile: local.join("Vivaldi"),
                    registration: Registration::RegistryKey(key("Vivaldi")),
                },
                Browser {
                    name: "Firefox",
                    family: Firefox,
                    profile: roaming.join("Mozilla").join("Firefox"),
                    registration: Registration::RegistryKey(key("Mozilla")),
                },
            ]
        }
    }
}

/// The browsers to register with: those that have been used here, or, when
/// none has, every known one so the helper is found once one is.
#[must_use]
pub fn select_browsers(all: Vec<Browser>, exists: impl Fn(&Path) -> bool) -> (Vec<Browser>, bool) {
    let found: Vec<Browser> = all.iter().filter(|b| exists(&b.profile)).cloned().collect();
    if found.is_empty() {
        (all, false)
    } else {
        (found, true)
    }
}

/// The host manifest for `family`, pointing at `binary`.
#[must_use]
pub fn manifest(family: Family, binary: &Path, allow: &Allowlist) -> Value {
    let mut value = json!({
        "name": HOST_NAME,
        "description": "Warren VPN helper",
        "path": binary.to_string_lossy(),
        "type": "stdio",
    });
    match family {
        Family::Chromium => value["allowed_origins"] = json!(allow.chromium_origins()),
        Family::Firefox => value["allowed_extensions"] = json!(allow.gecko),
    }
    value
}

/// Distinct display names, first-seen order ("Chrome, Edge, Firefox").
#[must_use]
pub fn display_names(browsers: &[Browser]) -> Vec<&'static str> {
    let mut names = Vec::new();
    for b in browsers {
        // "Chrome Beta" folds into "Chrome": one product for the reader.
        let short = b.name.split(' ').next().unwrap_or(b.name);
        let short: &'static str = match short {
            "Chrome" => "Chrome",
            "Brave" => "Brave",
            "Edge" => "Edge",
            _ => b.name,
        };
        if !names.contains(&short) {
            names.push(short);
        }
    }
    names
}

/// What an install did.
#[derive(Debug)]
pub struct InstallReport {
    /// The installed binary.
    pub binary: PathBuf,
    /// The browser display names registered.
    pub browsers: Vec<&'static str>,
    /// Whether those were found on the machine (else: every known one).
    pub detected: bool,
}

/// Validates the ids given on the command line.
///
/// # Errors
///
/// [`InstallError::BadId`] for the first malformed one.
pub fn validate_ids(extra: &ExtraIds) -> Result<(), InstallError> {
    if let Some(bad) = extra
        .extension_ids
        .iter()
        .find(|id| !crate::ids::is_chromium_id(id))
    {
        return Err(InstallError::BadId(bad.clone()));
    }
    if let Some(bad) = extra
        .gecko_ids
        .iter()
        .find(|id| !crate::ids::is_gecko_id(id))
    {
        return Err(InstallError::BadId(bad.clone()));
    }
    Ok(())
}

/// Installs the running binary `source` for the current user.
///
/// # Errors
///
/// [`InstallError`] when a file or registry write fails.
pub fn install(
    platform: &Platform,
    source: &Path,
    extra: &ExtraIds,
) -> Result<InstallReport, InstallError> {
    validate_ids(extra)?;
    let binary = platform.binary_path();
    place_binary(source, &binary)?;

    let record_path = platform.extra_ids_path();
    let record = ExtraIds::load(&record_path).merged(extra);
    write_file(
        &record_path,
        &serde_json::to_vec_pretty(&record).unwrap_or_default(),
    )?;
    let allow = Allowlist::new(BUILD_CHANNEL, &record);

    let (targets, detected) = select_browsers(browsers(platform), Path::exists);
    for browser in &targets {
        let file = browser.manifest_file(platform);
        let body = serde_json::to_vec_pretty(&manifest(browser.family, &binary, &allow))
            .unwrap_or_default();
        write_file(&file, &body)?;
        if let Registration::RegistryKey(key) = &browser.registration {
            registry::set_default(key, &file).map_err(|_| InstallError::Registry(key.clone()))?;
        }
    }
    Ok(InstallReport {
        binary,
        browsers: display_names(&targets),
        detected,
    })
}

/// What an uninstall removed and what it could not.
#[derive(Debug, Default)]
pub struct UninstallReport {
    /// Paths removed.
    pub removed: Vec<PathBuf>,
    /// Paths that could not be removed (a running helper on Windows).
    pub left: Vec<PathBuf>,
}

/// Removes every manifest, registry key, id record, state and the binary.
#[must_use]
pub fn uninstall(platform: &Platform) -> UninstallReport {
    let mut report = UninstallReport::default();
    for browser in browsers(platform) {
        if let Registration::RegistryKey(key) = &browser.registration {
            let _ = registry::delete(key);
        }
        let file = browser.manifest_file(platform);
        if file.exists() {
            match std::fs::remove_file(&file) {
                Ok(()) => report.removed.push(file),
                Err(_) => report.left.push(file),
            }
        }
    }
    let dir = platform.helper_dir();
    if dir.exists() {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => report.removed.push(dir),
            Err(_) => report.left.push(dir),
        }
    }
    report
}

/// Whether each known browser has the manifest.
#[must_use]
pub fn registrations(platform: &Platform) -> Vec<(Browser, bool)> {
    browsers(platform)
        .into_iter()
        .map(|b| {
            let file = b.manifest_file(platform);
            let registered = match &b.registration {
                Registration::Directory(_) => file.exists(),
                Registration::RegistryKey(key) => file.exists() && registry::exists(key),
            };
            (b, registered)
        })
        .collect()
}

fn write_file(path: &Path, body: &[u8]) -> Result<(), InstallError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_err("create", parent))?;
    }
    let tmp = sibling(path, "tmp");
    std::fs::write(&tmp, body).map_err(io_err("write", &tmp))?;
    std::fs::rename(&tmp, path).map_err(io_err("write", path))
}

fn sibling(path: &Path, tag: &str) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.{tag}-{}", std::process::id()))
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Copies `source` to `target` atomically: a browser starting the helper in
/// the middle of an update gets the old binary or the new one, never half.
fn place_binary(source: &Path, target: &Path) -> Result<(), InstallError> {
    if same_file(source, target) {
        return Ok(());
    }
    let dir = target.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(io_err("create", dir))?;
    let tmp = sibling(target, "new");
    std::fs::copy(source, &tmp).map_err(io_err("copy the helper to", &tmp))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(io_err("set permissions on", &tmp))?;
    }
    #[cfg(windows)]
    {
        // A running executable cannot be replaced, but it can be renamed:
        // move the old one aside and sweep it on a later install.
        if target.exists() {
            let aside = sibling(target, "old");
            std::fs::rename(target, &aside).map_err(io_err("move aside", target))?;
        }
    }
    std::fs::rename(&tmp, target).map_err(io_err("install", target))?;
    clear_download_marks(target);
    sweep_leftovers(dir);
    Ok(())
}

/// Drops the "downloaded from the internet" marks the copy inherited, so the
/// browser can start it without a prompt nobody would see.
fn clear_download_marks(path: &Path) {
    #[cfg(windows)]
    {
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        let _ = std::fs::remove_file(PathBuf::from(stream));
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/usr/bin/xattr")
            .args(["-d", "com.apple.quarantine"])
            .arg(path)
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    let _ = path;
}

/// Removes binaries moved aside by earlier updates, once nothing runs them.
fn sweep_leftovers(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".warren-host") && name.contains(".old-") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(windows)]
mod registry {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    /// `reg.exe` from System32, never whatever the PATH resolves first.
    fn reg() -> Command {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let mut command = Command::new(PathBuf::from(root).join("System32").join("reg.exe"));
        command.stdout(Stdio::null()).stderr(Stdio::null());
        command
    }

    pub(super) fn set_default(key: &str, value: &Path) -> std::io::Result<()> {
        let status = reg()
            .args(["add", &format!("HKCU\\{key}"), "/ve", "/t", "REG_SZ", "/d"])
            .arg(value)
            .arg("/f")
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other("reg add failed"))
        }
    }

    pub(super) fn delete(key: &str) -> std::io::Result<()> {
        reg()
            .args(["delete", &format!("HKCU\\{key}"), "/f"])
            .status()
            .map(|_| ())
    }

    pub(super) fn exists(key: &str) -> bool {
        reg()
            .args(["query", &format!("HKCU\\{key}"), "/ve"])
            .status()
            .is_ok_and(|s| s.success())
    }
}

#[cfg(not(windows))]
mod registry {
    //! Only Windows registers through the registry; elsewhere no browser
    //! entry carries a key, so these are never reached.
    use std::path::Path;

    pub(super) fn set_default(_key: &str, _value: &Path) -> std::io::Result<()> {
        Err(std::io::Error::other("no registry on this platform"))
    }

    pub(super) fn delete(_key: &str) -> std::io::Result<()> {
        Ok(())
    }

    pub(super) fn exists(_key: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use warren_sdk::product::Channel;

    use super::*;

    fn platform(os: Os) -> Platform {
        Platform {
            os,
            home: PathBuf::from("/h"),
            xdg_config_home: None,
            xdg_data_home: None,
            local_app_data: None,
            app_data: None,
        }
    }

    fn windows() -> Platform {
        Platform {
            os: Os::Windows,
            home: PathBuf::from(r"C:\Users\u"),
            xdg_config_home: None,
            xdg_data_home: None,
            local_app_data: Some(PathBuf::from(r"C:\Users\u\AppData\Local")),
            app_data: Some(PathBuf::from(r"C:\Users\u\AppData\Roaming")),
        }
    }

    fn find<'a>(all: &'a [Browser], name: &str) -> &'a Browser {
        all.iter()
            .find(|b| b.name == name)
            .unwrap_or_else(|| panic!("{name}"))
    }

    #[test]
    fn installs_under_the_per_user_data_directory() {
        assert_eq!(
            platform(Os::MacOs).binary_path(),
            PathBuf::from("/h/Library/Application Support/Warren/Helper/warren-host")
        );
        assert_eq!(
            platform(Os::Linux).binary_path(),
            PathBuf::from("/h/.local/share/warren/helper/warren-host")
        );
        let xdg = Platform {
            xdg_data_home: Some(PathBuf::from("/x")),
            ..platform(Os::Linux)
        };
        assert_eq!(
            xdg.binary_path(),
            PathBuf::from("/x/warren/helper/warren-host")
        );
        assert_eq!(
            windows().binary_path(),
            PathBuf::from(r"C:\Users\u\AppData\Local")
                .join("Warren")
                .join("Helper")
                .join("warren-host.exe")
        );
        assert_eq!(
            platform(Os::MacOs).state_dir(),
            PathBuf::from("/h/Library/Application Support/Warren/Helper/state")
        );
    }

    #[test]
    fn registers_with_the_macos_browsers_in_their_own_directories() {
        let all = browsers(&platform(Os::MacOs));
        let support = PathBuf::from("/h/Library/Application Support");
        let expect = [
            ("Chrome", "Google/Chrome"),
            ("Chromium", "Chromium"),
            ("Brave", "BraveSoftware/Brave-Browser"),
            ("Edge", "Microsoft Edge"),
            ("Vivaldi", "Vivaldi"),
            ("Arc", "Arc/User Data"),
            ("Opera", "com.operasoftware.Opera"),
            ("Firefox", "Mozilla"),
            ("LibreWolf", "LibreWolf"),
        ];
        for (name, dir) in expect {
            assert_eq!(
                find(&all, name).registration,
                Registration::Directory(support.join(dir).join("NativeMessagingHosts")),
                "{name}"
            );
        }
        assert_eq!(find(&all, "Firefox").family, Family::Firefox);
        assert_eq!(find(&all, "Firefox").profile, support.join("Firefox"));
        assert_eq!(find(&all, "Chrome").family, Family::Chromium);
    }

    #[test]
    fn registers_with_the_linux_browsers_honouring_xdg_config_home() {
        let all = browsers(&platform(Os::Linux));
        assert_eq!(
            find(&all, "Chrome").registration,
            Registration::Directory(PathBuf::from(
                "/h/.config/google-chrome/NativeMessagingHosts"
            ))
        );
        assert_eq!(
            find(&all, "Firefox").registration,
            Registration::Directory(PathBuf::from("/h/.mozilla/native-messaging-hosts"))
        );
        let xdg = Platform {
            xdg_config_home: Some(PathBuf::from("/c")),
            ..platform(Os::Linux)
        };
        assert_eq!(
            find(&browsers(&xdg), "Brave").registration,
            Registration::Directory(PathBuf::from(
                "/c/BraveSoftware/Brave-Browser/NativeMessagingHosts"
            ))
        );
    }

    #[test]
    fn registers_with_the_windows_browsers_through_hkcu_keys() {
        let p = windows();
        let all = browsers(&p);
        for (name, vendor) in [
            ("Chrome", "Google\\Chrome"),
            ("Chromium", "Chromium"),
            ("Edge", "Microsoft\\Edge"),
            ("Brave", "BraveSoftware\\Brave-Browser"),
            ("Vivaldi", "Vivaldi"),
            ("Firefox", "Mozilla"),
        ] {
            assert_eq!(
                find(&all, name).registration,
                Registration::RegistryKey(format!(
                    "Software\\{vendor}\\NativeMessagingHosts\\com.warrenbrowse.host"
                )),
                "{name}"
            );
        }
        assert_eq!(
            find(&all, "Edge").manifest_file(&p),
            p.helper_dir().join("com.warrenbrowse.host.chromium.json")
        );
        assert_eq!(
            find(&all, "Firefox").manifest_file(&p),
            p.helper_dir().join("com.warrenbrowse.host.firefox.json")
        );
    }

    #[test]
    fn registers_with_the_browsers_in_use_or_all_when_none_is() {
        let all = browsers(&platform(Os::MacOs));
        let used = PathBuf::from("/h/Library/Application Support/Firefox");
        let (picked, detected) = select_browsers(all.clone(), |p| p == used);
        assert!(detected);
        assert_eq!(display_names(&picked), ["Firefox"]);
        let (picked, detected) = select_browsers(all.clone(), |_| false);
        assert!(!detected);
        assert_eq!(picked.len(), all.len());
    }

    #[test]
    fn writes_each_family_its_own_caller_field() {
        let allow = Allowlist::new(Channel::Beta, &ExtraIds::default());
        let binary = Path::new("/h/bin/warren-host");
        assert_eq!(
            manifest(Family::Chromium, binary, &allow),
            json!({
                "name": "com.warrenbrowse.host",
                "description": "Warren VPN helper",
                "path": "/h/bin/warren-host",
                "type": "stdio",
                "allowed_origins": ["chrome-extension://dgkleicjbkfinjhhhmalipaepnlchfib/"],
            })
        );
        assert_eq!(
            manifest(Family::Firefox, binary, &allow)["allowed_extensions"],
            json!(["vpn-beta@warrenbrowse.com"])
        );
    }

    #[test]
    fn names_each_product_once() {
        let all = browsers(&platform(Os::MacOs));
        let names = display_names(&all);
        assert_eq!(
            names,
            [
                "Chrome",
                "Chromium",
                "Brave",
                "Edge",
                "Vivaldi",
                "Arc",
                "Opera",
                "Firefox",
                "LibreWolf"
            ]
        );
    }

    #[test]
    fn refuses_a_malformed_id_before_writing_anything() {
        let extra = ExtraIds {
            extension_ids: vec!["not-an-id".into()],
            gecko_ids: Vec::new(),
        };
        assert!(matches!(validate_ids(&extra), Err(InstallError::BadId(_))));
        let extra = ExtraIds {
            extension_ids: Vec::new(),
            gecko_ids: vec!["\"quoted\"@x".into()],
        };
        assert!(matches!(validate_ids(&extra), Err(InstallError::BadId(_))));
    }
}
