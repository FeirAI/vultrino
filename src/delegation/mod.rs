//! Delegation grant evaluation (plan 031 D3) — fail-closed floors for delegate-agent
//! approvals at the vultrino decide path (before status transitions to Approved).

use serde::{Deserialize, Serialize};

/// Snapshot of a govder DelegationGrant scope, bound to a `vap_` token at mint time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationGrantScope {
    /// Maximum risk tier the delegate may approve (Low or Medium in v1).
    pub max_risk_tier: String,
    /// Allowed action classes; empty means all actions permitted within risk cap.
    #[serde(default)]
    pub action_classes: Vec<String>,
}

impl Default for DelegationGrantScope {
    fn default() -> Self {
        Self {
            max_risk_tier: "Low".to_string(),
            action_classes: Vec::new(),
        }
    }
}

impl DelegationGrantScope {
    pub fn validate(&self) -> Result<(), String> {
        let tier = self.max_risk_tier.trim();
        if tier.is_empty() {
            return Err("grant_scope.max_risk_tier is required".to_string());
        }
        if tier != "Low" && tier != "Medium" {
            return Err(format!(
                "grant_scope.max_risk_tier {tier:?} is not permitted in v1 (only Low/Medium)"
            ));
        }
        Ok(())
    }
}

/// Inputs for evaluating a delegate verdict against grant caps + D3 human floors.
#[derive(Debug, Clone)]
pub struct DelegateEvalInput<'a> {
    pub grant_scope: &'a DelegationGrantScope,
    pub delegate_agent_id: &'a str,
    pub action_class: &'a str,
    pub risk_tier: &'a str,
    pub irreversible: bool,
    pub approve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateEvalResult {
    pub permitted: bool,
    pub reason: String,
}

/// Evaluate a delegate approval verdict. Mirrors govder delegation/evaluate.go D3 floors.
pub fn evaluate_delegate_decision(input: DelegateEvalInput<'_>) -> DelegateEvalResult {
    let deny = |reason: &str| DelegateEvalResult {
        permitted: false,
        reason: reason.to_string(),
    };

    if input.delegate_agent_id.trim().is_empty() {
        return deny("delegation: delegate identity is required (fail-closed)");
    }

    if input.irreversible {
        return deny("delegation: irreversible actions require human approval (D3 floor)");
    }

    let risk = input.risk_tier.trim();
    if risk.is_empty() {
        return deny("delegation: risk_tier is required for delegate evaluation (fail-closed)");
    }

    let risk_strength = match risk {
        "Low" => 1,
        "Medium" => 2,
        "High" => 3,
        "Extreme" => 4,
        _ => return deny(&format!("delegation: unknown risk_tier {risk:?} (fail-closed)")),
    };

    let max = input.grant_scope.max_risk_tier.trim();
    let max_strength = match max {
        "Low" => 1,
        "Medium" => 2,
        _ => return deny(&format!("delegation: invalid grant max_risk_tier {max:?} (fail-closed)")),
    };

    if risk_strength > max_strength {
        return deny(&format!(
            "delegation: risk tier {risk} exceeds grant cap {max} (fail-closed)"
        ));
    }

    if risk == "High" || risk == "Extreme" {
        return deny("delegation: High/Extreme risk requires human approval (D3 floor)");
    }

    if !input.grant_scope.action_classes.is_empty() {
        let action = input.action_class.trim();
        if action.is_empty() {
            return deny("delegation: action class is required when grant scopes actions (fail-closed)");
        }
        if !input
            .grant_scope
            .action_classes
            .iter()
            .any(|a| a.trim() == action)
        {
            return deny(&format!(
                "delegation: action class {action:?} not in grant scope (fail-closed)"
            ));
        }
    }

    if !input.approve {
        return deny("delegate verdict denied");
    }

    DelegateEvalResult {
        permitted: true,
        reason: "delegate approved within grant caps".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_low() -> DelegationGrantScope {
        DelegationGrantScope {
            max_risk_tier: "Low".to_string(),
            action_classes: vec!["http.request".to_string()],
        }
    }

    #[test]
    fn low_risk_within_grant_allows() {
        let s = scope_low();
        let out = evaluate_delegate_decision(DelegateEvalInput {
            grant_scope: &s,
            delegate_agent_id: "delegate-bot",
            action_class: "http.request",
            risk_tier: "Low",
            irreversible: false,
            approve: true,
        });
        assert!(out.permitted);
    }

    #[test]
    fn high_risk_denied() {
        let s = scope_low();
        let out = evaluate_delegate_decision(DelegateEvalInput {
            grant_scope: &s,
            delegate_agent_id: "delegate-bot",
            action_class: "http.request",
            risk_tier: "High",
            irreversible: false,
            approve: true,
        });
        assert!(!out.permitted);
        assert!(out.reason.contains("High"));
    }

    #[test]
    fn irreversible_denied() {
        let s = scope_low();
        let out = evaluate_delegate_decision(DelegateEvalInput {
            grant_scope: &s,
            delegate_agent_id: "delegate-bot",
            action_class: "http.request",
            risk_tier: "Low",
            irreversible: true,
            approve: true,
        });
        assert!(!out.permitted);
        assert!(out.reason.contains("irreversible"));
    }

    #[test]
    fn empty_risk_tier_fail_closed() {
        let s = scope_low();
        let out = evaluate_delegate_decision(DelegateEvalInput {
            grant_scope: &s,
            delegate_agent_id: "delegate-bot",
            action_class: "http.request",
            risk_tier: "",
            irreversible: false,
            approve: true,
        });
        assert!(!out.permitted);
    }
}