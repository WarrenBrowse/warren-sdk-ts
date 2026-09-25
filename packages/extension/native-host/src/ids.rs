//! Which extensions may drive this helper: the ids baked for the build's
//! channel, plus the ids recorded at install time. The browser's manifest is
//! the first gate; this is the second, applied to the caller the browser names
//! on the command line.

use std::path::Path;

use serde::{Deserialize, Serialize};
use warren_sdk::product::{self, Channel};

/// The channel this build targets (`WARREN_PRODUCT_ENV` at compile time).
pub const BUILD_CHANNEL: Channel = product::CHANNEL;

/// The extension ids a channel's build trusts. The extension pins them through
/// its manifest `key` (Chromium) and `browser_specific_settings.gecko.id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BakedIds {
    /// Chromium extension ids.
    pub chromium: &'static [&'static str],
    /// Firefox add-on ids.
    pub gecko: &'static [&'static str],
}

/// The ids baked for `channel`.
#[must_use]
pub const fn baked_ids(channel: Channel) -> BakedIds {
    match channel {
        Channel::Beta => BakedIds {
            chromium: &["dgkleicjbkfinjhhhmalipaepnlchfib"],
            gecko: &["vpn-beta@warrenbrowse.com"],
        },
        Channel::Prod => BakedIds {
            chromium: &["icngiamijikflhcilcgfpeipelhomldk"],
            gecko: &["vpn@warrenbrowse.com"],
        },
    }
}

/// A Chromium extension id: 32 characters from `a` to `p`.
#[must_use]
pub fn is_chromium_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// A Firefox add-on id: `name@domain`, or a braced UUID.
#[must_use]
pub fn is_gecko_id(id: &str) -> bool {
    if let Some(inner) = id.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        return inner.len() == 36
            && inner.bytes().enumerate().all(|(i, b)| {
                matches!(i, 8 | 13 | 18 | 23) == (b == b'-') && (b == b'-' || b.is_ascii_hexdigit())
            });
    }
    let Some((name, domain)) = id.split_once('@') else {
        return false;
    };
    let name_ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
    let domain_ok = !domain.is_empty()
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b));
    name_ok && domain_ok
}

/// The extra ids recorded at install time, kept next to the binary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtraIds {
    /// Extra Chromium extension ids.
    #[serde(default)]
    pub extension_ids: Vec<String>,
    /// Extra Firefox add-on ids.
    #[serde(default)]
    pub gecko_ids: Vec<String>,
}

impl ExtraIds {
    /// The file name of the record, next to the installed binary.
    pub const FILE_NAME: &'static str = "warren-host.json";

    /// Reads the record at `path`. A missing or unreadable record is empty,
    /// and an entry that is not a valid id is dropped: a damaged file can
    /// only narrow who may call, never widen it.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let Ok(bytes) = std::fs::read(path) else {
            return Self::default();
        };
        let Ok(record) = serde_json::from_slice::<Self>(&bytes) else {
            return Self::default();
        };
        Self {
            extension_ids: record
                .extension_ids
                .into_iter()
                .filter(|id| is_chromium_id(id))
                .collect(),
            gecko_ids: record
                .gecko_ids
                .into_iter()
                .filter(|id| is_gecko_id(id))
                .collect(),
        }
    }

    /// `self` plus the ids of `other` it does not carry yet, in order.
    #[must_use]
    pub fn merged(mut self, other: &Self) -> Self {
        for id in &other.extension_ids {
            if !self.extension_ids.contains(id) {
                self.extension_ids.push(id.clone());
            }
        }
        for id in &other.gecko_ids {
            if !self.gecko_ids.contains(id) {
                self.gecko_ids.push(id.clone());
            }
        }
        self
    }
}

/// The extension a browser launched this helper for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// A Chromium extension, by id.
    Chromium(String),
    /// A Firefox add-on, by id.
    Firefox(String),
}

/// Recognises a browser launch from the arguments. Chromium passes the
/// caller origin `chrome-extension://<id>/` (and on Windows a
/// `--parent-window=` handle); Firefox passes the manifest path, then the
/// add-on id.
#[must_use]
pub fn caller_from_args(args: &[String]) -> Option<Caller> {
    if let Some(origin) = args
        .iter()
        .find_map(|a| a.strip_prefix("chrome-extension://"))
    {
        let id = origin.trim_end_matches('/');
        return Some(Caller::Chromium(id.to_owned()));
    }
    match args {
        [manifest, id, ..] if manifest.to_ascii_lowercase().ends_with(".json") => {
            Some(Caller::Firefox(id.clone()))
        }
        _ => None,
    }
}

/// The complete set of ids allowed to call a build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    /// Chromium extension ids.
    pub chromium: Vec<String>,
    /// Firefox add-on ids.
    pub gecko: Vec<String>,
}

impl Allowlist {
    /// The ids baked for `channel` plus the recorded extras.
    #[must_use]
    pub fn new(channel: Channel, extra: &ExtraIds) -> Self {
        let baked = baked_ids(channel);
        let own = ExtraIds {
            extension_ids: baked.chromium.iter().map(|s| (*s).to_owned()).collect(),
            gecko_ids: baked.gecko.iter().map(|s| (*s).to_owned()).collect(),
        }
        .merged(extra);
        Self {
            chromium: own.extension_ids,
            gecko: own.gecko_ids,
        }
    }

    /// Whether `caller` is on the list.
    #[must_use]
    pub fn admits(&self, caller: &Caller) -> bool {
        match caller {
            Caller::Chromium(id) => self.chromium.iter().any(|a| a == id),
            Caller::Firefox(id) => self.gecko.iter().any(|a| a == id),
        }
    }

    /// The Chromium manifest's `allowed_origins`.
    #[must_use]
    pub fn chromium_origins(&self) -> Vec<String> {
        self.chromium
            .iter()
            .map(|id| format!("chrome-extension://{id}/"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn every_baked_id_is_well_formed_and_the_channels_share_none() {
        for channel in [Channel::Prod, Channel::Beta] {
            let ids = baked_ids(channel);
            assert!(ids.chromium.iter().all(|id| is_chromium_id(id)));
            assert!(ids.gecko.iter().all(|id| is_gecko_id(id)));
        }
        let (prod, beta) = (baked_ids(Channel::Prod), baked_ids(Channel::Beta));
        assert!(prod.chromium.iter().all(|id| !beta.chromium.contains(id)));
        assert!(prod.gecko.iter().all(|id| !beta.gecko.contains(id)));
    }

    #[test]
    fn pins_the_ids_the_extension_manifests_carry() {
        assert_eq!(
            baked_ids(Channel::Beta).chromium,
            ["dgkleicjbkfinjhhhmalipaepnlchfib"]
        );
        assert_eq!(
            baked_ids(Channel::Beta).gecko,
            ["vpn-beta@warrenbrowse.com"]
        );
        assert_eq!(
            baked_ids(Channel::Prod).chromium,
            ["icngiamijikflhcilcgfpeipelhomldk"]
        );
        assert_eq!(baked_ids(Channel::Prod).gecko, ["vpn@warrenbrowse.com"]);
    }

    #[test]
    fn validates_extension_ids() {
        assert!(is_chromium_id("abcdefghijklmnopabcdefghijklmnop"));
        assert!(!is_chromium_id("abcdefghijklmnopabcdefghijklmnoq"));
        assert!(!is_chromium_id("abcdefghijklmnop"));
        assert!(is_gecko_id("warren@warrenbrowse.com"));
        assert!(is_gecko_id("{12345678-abcd-4bcd-8bcd-1234567890ab}"));
        assert!(!is_gecko_id("{12345678abcd-4bcd-8bcd-1234567890ab0}"));
        assert!(!is_gecko_id("no-at-sign"));
        assert!(!is_gecko_id("a@b\"c"));
        assert!(!is_gecko_id("@warrenbrowse.com"));
    }

    #[test]
    fn recognises_a_chromium_launch_on_every_platform() {
        let id = "dgkleicjbkfinjhhhmalipaepnlchfib";
        let unix = args(&[&format!("chrome-extension://{id}/")]);
        let windows = args(&[&format!("chrome-extension://{id}/"), "--parent-window=0"]);
        for launch in [unix, windows] {
            assert_eq!(caller_from_args(&launch), Some(Caller::Chromium(id.into())));
        }
    }

    #[test]
    fn recognises_a_firefox_launch() {
        let launch = args(&[
            "/home/u/.mozilla/native-messaging-hosts/com.warrenbrowse.host.json",
            "vpn@warrenbrowse.com",
        ]);
        assert_eq!(
            caller_from_args(&launch),
            Some(Caller::Firefox("vpn@warrenbrowse.com".into()))
        );
    }

    #[test]
    fn a_human_invocation_is_no_browser_launch() {
        for launch in [
            args(&[]),
            args(&["install"]),
            args(&["install", "--gecko-id", "a@b.c"]),
        ] {
            assert_eq!(caller_from_args(&launch), None);
        }
    }

    #[test]
    fn admits_the_channels_ids_and_the_recorded_extras_only() {
        let extra = ExtraIds {
            extension_ids: vec!["abcdefghijklmnopabcdefghijklmnop".into()],
            gecko_ids: vec!["dev@example.com".into()],
        };
        let beta = Allowlist::new(Channel::Beta, &extra);
        assert!(beta.admits(&Caller::Chromium("dgkleicjbkfinjhhhmalipaepnlchfib".into())));
        assert!(beta.admits(&Caller::Chromium("abcdefghijklmnopabcdefghijklmnop".into())));
        assert!(beta.admits(&Caller::Firefox("vpn-beta@warrenbrowse.com".into())));
        assert!(beta.admits(&Caller::Firefox("dev@example.com".into())));
        assert!(!beta.admits(&Caller::Chromium("icngiamijikflhcilcgfpeipelhomldk".into())));
        assert!(!beta.admits(&Caller::Firefox("vpn@warrenbrowse.com".into())));
        // A gecko id is no Chromium id, whatever the list holds.
        assert!(!beta.admits(&Caller::Chromium("dev@example.com".into())));
    }

    #[test]
    fn a_damaged_record_only_narrows_the_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ExtraIds::FILE_NAME);
        assert_eq!(ExtraIds::load(&path), ExtraIds::default());
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(ExtraIds::load(&path), ExtraIds::default());
        std::fs::write(
            &path,
            r#"{"extensionIds":["abcdefghijklmnopabcdefghijklmnop","*"],"geckoIds":["x\"y@z","ok@example.com"]}"#,
        )
        .unwrap();
        assert_eq!(
            ExtraIds::load(&path),
            ExtraIds {
                extension_ids: vec!["abcdefghijklmnopabcdefghijklmnop".into()],
                gecko_ids: vec!["ok@example.com".into()],
            }
        );
    }

    #[test]
    fn merging_keeps_order_and_drops_duplicates() {
        let a = ExtraIds {
            extension_ids: vec!["a".into()],
            gecko_ids: vec!["x@y".into()],
        };
        let b = ExtraIds {
            extension_ids: vec!["b".into(), "a".into()],
            gecko_ids: vec!["x@y".into()],
        };
        let merged = a.merged(&b);
        assert_eq!(merged.extension_ids, ["a", "b"]);
        assert_eq!(merged.gecko_ids, ["x@y"]);
    }
}
