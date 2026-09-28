//! Operator-pinned Buffer social targets.
//!
//! Buffer pins are the only source of authority for the native Buffer
//! connector.  Requests select one of these aliases; they never supply a
//! provider account id directly.

use serde::Serialize;
use std::collections::{HashMap, HashSet};

const MAX_ID_LEN: usize = 128;

/// Buffer reports a LinkedIn channel's `serviceId` as a LinkedIn URN
/// (`urn:li:organization:135696968`), so `service_id` alone also admits that
/// form: lowercase `urn:li:`, one of these entity kinds, and a 1-64 character
/// `[A-Za-z0-9_-]` id. Nothing else with a colon is accepted.
const LINKEDIN_URN_PREFIX: &str = "urn:li:";
const LINKEDIN_URN_KINDS: &[&str] = &["organization", "person", "member"];
const MAX_LINKEDIN_URN_ID_LEN: usize = 64;

/// A service name understood by Buffer for one of the supported target aliases.
const X_SERVICE: &str = "twitter";
const LINKEDIN_SERVICE: &str = "linkedin";

/// One operator-pinned Buffer target.
///
/// `service_id` is the remote social-account id returned by Buffer.  It is
/// intentionally not an enum or a service name; [`Self::service`] derives the
/// provider service from `target_alias`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BufferPin {
    pub tenant_id: String,
    pub project_id: String,
    pub credential_alias: String,
    pub organization_id: String,
    pub target_alias: String,
    pub channel_id: String,
    pub service_id: String,
    pub account_id: String,
}

impl BufferPin {
    /// Parse and validate one pin from its eight TOML fields.
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        tenant_id: &str,
        project_id: &str,
        credential_alias: &str,
        organization_id: &str,
        target_alias: &str,
        channel_id: &str,
        service_id: &str,
        account_id: &str,
    ) -> Result<Self, String> {
        for (name, value) in [
            ("tenant_id", tenant_id),
            ("project_id", project_id),
            ("credential_alias", credential_alias),
            ("organization_id", organization_id),
            ("channel_id", channel_id),
            ("account_id", account_id),
        ] {
            validate_id(name, value)?;
        }
        validate_service_id(service_id)?;

        match target_alias {
            "x" | "linkedin" => {}
            other => {
                return Err(format!(
                    "buffer_pins: target_alias '{}' must be exactly x or linkedin",
                    other
                ));
            }
        }

        Ok(Self {
            tenant_id: tenant_id.to_string(),
            project_id: project_id.to_string(),
            credential_alias: credential_alias.to_string(),
            organization_id: organization_id.to_string(),
            target_alias: target_alias.to_string(),
            channel_id: channel_id.to_string(),
            service_id: service_id.to_string(),
            account_id: account_id.to_string(),
        })
    }

    /// Buffer's service name for this target alias.
    pub fn service(&self) -> &'static str {
        match self.target_alias.as_str() {
            "x" => X_SERVICE,
            "linkedin" => LINKEDIN_SERVICE,
            // A BufferPin cannot be constructed with an invalid alias through
            // `parse`; keeping this branch total makes the public method robust
            // if a struct is assembled inside this crate in the future.
            _ => unreachable!("BufferPin target_alias is validated at construction"),
        }
    }
}

/// Validate cross-pin invariants after each pin has been parsed.
///
/// A credential alias must identify one tenant/project/organization context.
/// Target aliases and channel ids are then unambiguous within that credential:
/// the same `(credential_alias, target_alias)` or channel may not be declared
/// twice.  Empty input is valid and means that the plugin has no authority.
pub fn validate_buffer_pins(pins: &[BufferPin]) -> Result<(), String> {
    let mut contexts: HashMap<&str, (&str, &str, &str)> = HashMap::new();
    let mut target_keys: HashSet<(&str, &str)> = HashSet::new();
    let mut channel_keys: HashSet<(&str, &str)> = HashSet::new();

    for pin in pins {
        let context = (
            pin.tenant_id.as_str(),
            pin.project_id.as_str(),
            pin.organization_id.as_str(),
        );
        if let Some(previous) = contexts.insert(pin.credential_alias.as_str(), context) {
            if previous != context {
                return Err(format!(
                    "buffer_pins: credential_alias '{}' spans multiple tenant/project/organization contexts",
                    pin.credential_alias
                ));
            }
        }

        let target_key = (pin.credential_alias.as_str(), pin.target_alias.as_str());
        if !target_keys.insert(target_key) {
            return Err(format!(
                "buffer_pins: duplicate credential_alias '{}' and target_alias '{}'",
                pin.credential_alias, pin.target_alias
            ));
        }

        let channel_key = (pin.credential_alias.as_str(), pin.channel_id.as_str());
        if !channel_keys.insert(channel_key) {
            return Err(format!(
                "buffer_pins: duplicate channel_id '{}' for credential_alias '{}'",
                pin.channel_id, pin.credential_alias
            ));
        }
    }

    Ok(())
}

fn validate_id(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_ID_LEN || !value.is_ascii() {
        return Err(format!(
            "buffer_pins: {} must be 1-128 ASCII characters from [A-Za-z0-9_-]",
            name
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(format!(
            "buffer_pins: {} must contain only [A-Za-z0-9_-]",
            name
        ));
    }
    if is_obvious_placeholder(value) {
        return Err(format!(
            "buffer_pins: {} must not be an obvious placeholder",
            name
        ));
    }
    Ok(())
}

/// `service_id` is either a safe id (the X form, a numeric account id) or a
/// LinkedIn URN; see [`LINKEDIN_URN_PREFIX`]. It is only ever compared
/// byte-exactly against Buffer's channel record, never interpolated.
fn validate_service_id(value: &str) -> Result<(), String> {
    if is_linkedin_urn(value) {
        return Ok(());
    }
    validate_id("service_id", value).map_err(|_| {
        "buffer_pins: service_id must be 1-128 characters from [A-Za-z0-9_-] or \
         urn:li:(organization|person|member):<1-64 of [A-Za-z0-9_-]>"
            .to_string()
    })
}

fn is_linkedin_urn(value: &str) -> bool {
    if value.len() > MAX_ID_LEN {
        return false;
    }
    let Some((kind, id)) = value
        .strip_prefix(LINKEDIN_URN_PREFIX)
        .and_then(|rest| rest.split_once(':'))
    else {
        return false;
    };
    LINKEDIN_URN_KINDS.contains(&kind)
        && !id.is_empty()
        && id.len() <= MAX_LINKEDIN_URN_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && !is_obvious_placeholder(id)
}

fn is_obvious_placeholder(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "placeholder"
            | "example"
            | "changeme"
            | "change-me"
            | "replace-me"
            | "your-id"
            | "your_id"
            | "todo"
            | "test"
            | "none"
            | "null"
            | "undefined"
            | "n/a"
            | "na"
            | "foo"
            | "bar"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn pin(credential_alias: &str, target_alias: &str, channel_id: &str) -> BufferPin {
        BufferPin::parse(
            "tenant-a",
            "project-a",
            credential_alias,
            "org-a",
            target_alias,
            channel_id,
            "remote-123",
            "owner-x",
        )
        .unwrap()
    }

    #[test]
    fn valid_pins_derive_services_and_allow_safe_aliases() {
        let x = pin("cred-buffer", "x", "channel-x");
        let linkedin = pin("cred-buffer", "linkedin", "channel-linkedin");
        assert_eq!(x.service(), "twitter");
        assert_eq!(linkedin.service(), "linkedin");
        assert!(validate_buffer_pins(&[x, linkedin]).is_ok());
    }

    #[test]
    fn empty_pin_list_is_valid_and_denies_by_absence() {
        assert!(validate_buffer_pins(&[]).is_ok());
        assert!(Config::parse("").unwrap().buffer_pins.is_empty());
        assert!(Config::default().buffer_pins.is_empty());
    }

    #[test]
    fn parser_rejects_bad_identity_target_and_placeholder_values() {
        assert!(
            BufferPin::parse("", "project-a", "cred", "org", "x", "ch", "sid", "acct").is_err()
        );
        assert!(BufferPin::parse(
            "tenant a",
            "project-a",
            "cred",
            "org",
            "x",
            "ch",
            "sid",
            "acct"
        )
        .is_err());
        assert!(BufferPin::parse(
            "tenant-a",
            "project-a",
            "cred",
            "org",
            "mastodon",
            "ch",
            "sid",
            "acct"
        )
        .is_err());
        assert!(BufferPin::parse(
            "tenant-a",
            "project-a",
            "placeholder",
            "org",
            "x",
            "ch",
            "sid",
            "acct"
        )
        .is_err());
        assert!(BufferPin::parse(
            "tenant-a",
            "project-a",
            "cred",
            "org",
            "x",
            "ch",
            "sid",
            "acct.with.dot"
        )
        .is_err());
    }

    #[test]
    fn list_validation_rejects_ambiguous_duplicates_and_contexts() {
        let first = pin("cred", "x", "ch-x");
        let duplicate_target = pin("cred", "x", "ch-other");
        assert!(validate_buffer_pins(&[first.clone(), duplicate_target]).is_err());

        let duplicate_channel = pin("cred", "linkedin", "ch-x");
        assert!(validate_buffer_pins(&[first.clone(), duplicate_channel]).is_err());

        let mut other_context = pin("cred", "linkedin", "ch-linkedin");
        other_context.project_id = "project-b".to_string();
        assert!(validate_buffer_pins(&[first, other_context]).is_err());
    }

    #[test]
    fn toml_requires_exact_eight_fields_and_loads_pins() {
        let config = Config::parse(
            "[[buffer_pins]]\n\
             tenant_id = \"tenant-a\"\n\
             project_id = \"project-a\"\n\
             credential_alias = \"cred-buffer\"\n\
             organization_id = \"org-a\"\n\
             target_alias = \"x\"\n\
             channel_id = \"channel-x\"\n\
             service_id = \"remote-x\"\n\
             account_id = \"owner-x\"\n",
        )
        .unwrap();
        assert_eq!(config.buffer_pins.len(), 1);
        assert_eq!(config.buffer_pins[0].service(), "twitter");

        let missing = "[[buffer_pins]]\ntenant_id = \"tenant-a\"\n";
        assert!(Config::parse(missing).is_err());

        let unknown = "[[buffer_pins]]\ntenant_id = \"tenant-a\"\nproject_id = \"project-a\"\ncredential_alias = \"cred\"\norganization_id = \"org\"\ntarget_alias = \"x\"\nchannel_id = \"ch\"\nservice_id = \"sid\"\naccount_id = \"acct\"\nextra = \"nope\"\n";
        assert!(Config::parse(unknown).is_err());
    }

    fn linkedin_pin(service_id: &str) -> Result<BufferPin, String> {
        BufferPin::parse(
            "tenant-a",
            "project-a",
            "cred-buffer",
            "org-a",
            "linkedin",
            "channel-linkedin",
            service_id,
            "owner-x",
        )
    }

    #[test]
    fn service_id_accepts_linkedin_urns_and_the_numeric_x_id() {
        for accepted in [
            "urn:li:organization:135696968",
            "urn:li:person:AbC-12_x",
            "urn:li:member:42",
            "2084242309374156800",
        ] {
            let pin = linkedin_pin(accepted).unwrap_or_else(|e| panic!("{accepted}: {e}"));
            assert_eq!(pin.service_id, accepted, "stored byte-exactly");
        }
        let longest = format!("urn:li:organization:{}", "9".repeat(64));
        assert!(linkedin_pin(&longest).is_ok());
    }

    #[test]
    fn service_id_rejects_anything_else_with_a_colon() {
        let too_long_id = format!("urn:li:organization:{}", "9".repeat(65));
        let over_128 = format!("urn:li:organization:{}", "9".repeat(120));
        for rejected in [
            "urn:li:organization:",
            "urn:li:organization",
            "urn:li::135696968",
            "urn:li:company:135696968",
            "urn:x:organization:135696968",
            "urn:li:organization:1:2",
            "URN:li:organization:135696968",
            "urn:LI:organization:135696968",
            "urn:li:Organization:135696968",
            "urn:li:organization:135 696968",
            "urn:li:organization:135696968 ",
            " urn:li:organization:135696968",
            "urn:li:organization:\"135696968\"",
            "urn:li:organization:135696968\n",
            "urn:li:organization:1356/96968",
            "urn:li:organization:test",
            "135696968:urn:li:organization",
            too_long_id.as_str(),
            over_128.as_str(),
        ] {
            let error = linkedin_pin(rejected).expect_err(rejected);
            assert!(error.contains("service_id"), "{rejected}: {error}");
        }
    }

    #[test]
    fn other_fields_still_refuse_a_colon() {
        let urn = "urn:li:organization:135696968";
        assert!(BufferPin::parse(
            "tenant-a",
            "project-a",
            "cred",
            "org",
            "linkedin",
            urn,
            "sid",
            "acct"
        )
        .is_err());
        assert!(BufferPin::parse(
            "tenant-a",
            "project-a",
            "cred",
            urn,
            "linkedin",
            "ch",
            "sid",
            "acct"
        )
        .is_err());
        assert!(BufferPin::parse(
            "tenant-a",
            "project-a",
            "cred",
            "org",
            "linkedin",
            "ch",
            "sid",
            urn
        )
        .is_err());
    }

    #[test]
    fn toml_round_trips_a_linkedin_urn_service_id() {
        let config = Config::parse(
            "[[buffer_pins]]\n\
             tenant_id = \"tenant-a\"\n\
             project_id = \"project-a\"\n\
             credential_alias = \"cred-buffer\"\n\
             organization_id = \"org-a\"\n\
             target_alias = \"linkedin\"\n\
             channel_id = \"channel-linkedin\"\n\
             service_id = \"urn:li:organization:135696968\"\n\
             account_id = \"owner-x\"\n",
        )
        .unwrap();
        assert_eq!(config.buffer_pins.len(), 1);
        assert_eq!(
            config.buffer_pins[0].service_id,
            "urn:li:organization:135696968"
        );
        assert_eq!(config.buffer_pins[0].service(), "linkedin");
    }
}
