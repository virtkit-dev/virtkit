//! What the hub keeps of a placed job's egress report ([`EgressReport`], `docs/fleet-design.md`,
//! *Job egress from the hub*): a node's report held to its bounds again, the newest kept.

use vk_hub_proto::egress::EgressReport;

/// The report to keep of `stored` and `incoming`: the one with the higher revision, `incoming`
/// on a tie, held to its bounds ([`EgressReport::bounded`]). A report is a cumulative snapshot,
/// so a replay replaces the counts rather than adding to them.
pub fn newest(
    stored: Option<EgressReport>,
    incoming: Option<EgressReport>,
) -> Option<EgressReport> {
    let incoming = incoming.map(EgressReport::bounded);
    match (stored, incoming) {
        (Some(s), Some(i)) if s.revision > i.revision => Some(s),
        (s, None) => s,
        (_, i) => i,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(revision: u64) -> EgressReport {
        EgressReport {
            revision,
            ..EgressReport::default()
        }
    }

    #[test]
    fn the_newest_report_is_kept() {
        let rev = |r: Option<EgressReport>| r.map(|r| r.revision);
        assert_eq!(rev(newest(Some(report(2)), Some(report(1)))), Some(2));
        assert_eq!(rev(newest(Some(report(1)), Some(report(2)))), Some(2));
        assert_eq!(rev(newest(None, Some(report(1)))), Some(1));
        assert_eq!(rev(newest(Some(report(1)), None)), Some(1));
        assert_eq!(rev(newest(None, None)), None);
        // A tie takes the incoming one, held to the bounds.
        let mut incoming = report(3);
        incoming.refusals_omitted = 7;
        incoming.refusals = vec![
            vk_hub_proto::egress::EgressRefusal {
                variable: "MICROVM_EGRESS_ALLOW_NAME\x1b[2J".into(),
                entry: "evil.com".into(),
                dimension: vk_hub_proto::egress::EgressDimension::Name,
                phase: vk_hub_proto::egress::EgressPhase::Run,
                source: vk_hub_proto::egress::EgressSource::Job,
                layer: None,
                reason: vk_hub_proto::egress::RefusalReason::InvalidEntry,
            };
            vk_hub_proto::egress::MAX_EGRESS_REFUSALS + 1
        ];
        let kept = newest(Some(report(3)), Some(incoming)).unwrap();
        assert_eq!(
            kept.refusals.len(),
            vk_hub_proto::egress::MAX_EGRESS_REFUSALS
        );
        assert_eq!(kept.refusals_omitted, 8);
        assert!(!kept.refusals[0].variable.contains('\x1b'));
    }
}
