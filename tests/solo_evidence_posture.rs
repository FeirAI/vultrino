//! VUL-38: the evidence posture the FeirOS Solo config ships parses to what the limitation text
//! says. The block below is copied from feir-os `deploy/vultrino.toml.template`; feir-os pins the
//! same lines in `operatorconfig_test.go`, so a change to one side fails the other's test.

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
d8_evidence_floor = "money_and_irreversible"
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
    let explicit_line = "d8_evidence_floor = \"money_and_irreversible\"\n";
    assert!(
        SOLO_AVERIN_BLOCK.contains(explicit_line),
        "Solo sets the floor explicitly"
    );
    let shipped = Config::parse(SOLO_AVERIN_BLOCK).unwrap();
    assert_eq!(
        shipped.averin.d8_evidence_floor,
        D8EvidenceFloor::MoneyAndIrreversible
    );
    // The key absent: the default, which is also what AverinConfig::default() carries.
    let absent = Config::parse(&SOLO_AVERIN_BLOCK.replace(explicit_line, "")).unwrap();
    assert_eq!(
        absent.averin.d8_evidence_floor,
        D8EvidenceFloor::MoneyAndIrreversible
    );
    assert_eq!(
        vultrino::averin::AverinConfig::default().d8_evidence_floor,
        D8EvidenceFloor::MoneyAndIrreversible
    );
    let human =
        Config::parse(&SOLO_AVERIN_BLOCK.replace("money_and_irreversible", "human_floor")).unwrap();
    assert_eq!(human.averin.d8_evidence_floor, D8EvidenceFloor::HumanFloor);
    let err = Config::parse(&SOLO_AVERIN_BLOCK.replace("money_and_irreversible", "routine"))
        .expect_err("an unknown floor must be refused at load");
    assert!(err.to_string().contains("d8_evidence_floor"), "{err}");
}
