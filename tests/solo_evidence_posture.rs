//! VUL-38: the evidence posture the FeirOS Solo config ships parses to what the limitation text
//! says. The block below is copied from feir-os `deploy/vultrino.toml.template`; feir-os pins the
//! same three lines in `operatorconfig_test.go`, so a change to one side fails the other's test.

use vultrino::averin::{AverinMode, D8EvidenceFloor};
use vultrino::config::Config;

const SOLO_AVERIN_BLOCK: &str = r#"
[averin]
enabled = true
base_url = "http://127.0.0.1:8080"
project_id = "acme"
session_id = "vultrino"
resource_id = "feir-os-credential-actions"
mode = "observe"
durable = false
timeout_secs = 30
d8_complete_evidence = true
grant_ttl_secs = 900
"#;

#[test]
fn the_solo_averin_block_is_observe_two_phase_and_not_durable() {
    let cfg = Config::parse(SOLO_AVERIN_BLOCK).expect("the shipped block must load");
    let av = cfg.averin;
    assert!(av.enabled);
    assert_eq!(av.mode, AverinMode::Observe);
    assert!(
        av.d8_complete_evidence,
        "Solo keeps two-phase evidence on for every action while Averin is up"
    );
    assert!(
        !av.durable,
        "the durable queue would make backup refuse a running service"
    );
}

#[test]
fn the_evidence_floor_defaults_to_money_and_irreversible_and_refuses_unknown_values() {
    let cfg = Config::parse(SOLO_AVERIN_BLOCK).unwrap();
    assert_eq!(
        cfg.averin.d8_evidence_floor,
        D8EvidenceFloor::MoneyAndIrreversible
    );
    let human = Config::parse(&format!(
        "{SOLO_AVERIN_BLOCK}d8_evidence_floor = \"human_floor\"\n"
    ))
    .unwrap();
    assert_eq!(human.averin.d8_evidence_floor, D8EvidenceFloor::HumanFloor);
    let explicit = Config::parse(&format!(
        "{SOLO_AVERIN_BLOCK}d8_evidence_floor = \"money_and_irreversible\"\n"
    ))
    .unwrap();
    assert_eq!(
        explicit.averin.d8_evidence_floor,
        D8EvidenceFloor::MoneyAndIrreversible
    );
    let err = Config::parse(&format!(
        "{SOLO_AVERIN_BLOCK}d8_evidence_floor = \"routine\"\n"
    ))
    .expect_err("an unknown floor must be refused at load");
    assert!(err.to_string().contains("d8_evidence_floor"), "{err}");
}
