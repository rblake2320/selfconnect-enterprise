# Test Registry — Named Coverage Inventory

This document is a maintained inventory of named test coverage across related
repositories. It is not automatically exhaustive and its totals are historical
until regenerated for a specific commit. Unit tests may use deterministic test
doubles or monkeypatching; integration and live-conformance sections state
explicitly when they exercise real processes, stores, cryptography, or Windows
targets. A unit-test count is never a substitute for live acceptance evidence.

## Grand Total

### Current SelfConnect Enterprise Checkout

The 2026-07-15 hardening checkout (commit containing
[LOG-20260715-006](LOG.md#log-20260715-006)) collected and passed **1,429 Python
tests on Windows with zero skips**. Pytest auto-started the real development
Ultra Node process and the Python live contract used real HTTP and
cryptography. Two expected warnings stated that no live-verified immutable sink
was configured in the relevant negative tests. Separate production-mode
evidence used real local PostgreSQL 17.5 and Redis 7.4.5: **16/16 Node tests,
39 live Node checks, and 84 live Python tests**, followed by rotated-TSK process
restart continuity. The live Node contract rewound four completed lifecycle
rows to `processing` and recovered them without duplicating their resources.
It also refused recovery after the underlying key became inactive and did not
create a replacement.
These results do not establish external storage,
authorization, or partner-adapter behavior.

The tables below retain historical per-repository inventories and should not be
summed as a current release total because some SDK coverage appears in more
than one checkout.

| Repo | Test Files | Named Tests | Notes |
| :--- | :--- | :--- | :--- |
| `selfconnect-enterprise` (core tests) | 32 | 882 | 130 skip on Linux (CNG/Windows), 21 skip without live server |
| `selfconnect-enterprise` (SDK tests) | 8 | 159 | 69 skip on Linux (Windows ctypes) |
| `selfconnect` (Win32 SDK) | 1 | 51 | 6 skip headless (display-dependent) |
| `selfconnect` (SDK tests) | 8 | 159 | 69 skip on Linux (Windows ctypes) |
| `tsk-protocol` (unit tests) | 1 | 36 | All pass |
| `tsk-protocol` (attack suite) | 1 | 12 attack scenarios | ~389,076 total attempts across all attacks |
| `tsk-protocol` (adversarial proof) | 1 | 6 adversarial scenarios | Full flow + 5 attack proofs |
| `tsk-protocol` (ultra bridge) | 1 | 11 bridge scenarios | BPC+TSK 7-layer verification |
| `bpc-protocol` (crypto) | 1 | 8 | All pass |
| `bpc-protocol` (client SDK) | 1 | 22 | All pass |
| `bpc-protocol` (server) | 1 | 26 | All pass |
| `bpc-protocol` (security hardening) | 1 | 45 | All pass |
| `words-of-wisdom` | 2 | 12 | Separate app, auth + quotes |

---

## selfconnect-enterprise — Core Tests (882 on Linux / 905 on Windows)


### Observer / Training Pipeline Filter — `test_enterprise/test_observer.py` (81 tests)

- `TestObserverFilter::test_default_accepts_allow_entry`
- `TestObserverFilter::test_default_rejects_deny`
- `TestObserverFilter::test_default_rejects_quarantined`
- `TestObserverFilter::test_seq_zero_rejected_by_default`
- `TestObserverFilter::test_min_seq_respected`
- `TestObserverFilter::test_policy_id_whitelist_pass`
- `TestObserverFilter::test_policy_id_whitelist_block`
- `TestObserverFilter::test_empty_policy_id_whitelist_accepts_any`
- `TestObserverFilter::test_max_classification_unclassified`
- `TestObserverFilter::test_max_classification_secret`
- `TestObserverFilter::test_max_classification_top_secret`
- `TestObserverFilter::test_action_whitelist_pass`
- `TestObserverFilter::test_action_whitelist_block`
- `TestObserverFilter::test_empty_action_whitelist_accepts_any`
- `TestObserverFilter::test_approval_mode_filter_autonomous`
- `TestObserverFilter::test_approval_mode_filter_human_approved`
- `TestObserverFilter::test_default_approval_modes_accept_both`
- `TestObserverFilter::test_all_criteria_must_match`
- `TestObserverFilter::test_unknown_classification_treated_as_rank_minus1`
- `TestRedactionConfig::test_no_redaction_returns_copy`
- `TestRedactionConfig::test_remove_fields`
- `TestRedactionConfig::test_remove_nonexistent_field_is_safe`
- `TestRedactionConfig::test_mask_fields`
- `TestRedactionConfig::test_mask_nonexistent_field_is_safe`
- `TestRedactionConfig::test_input_not_mutated`
- `TestRedactionConfig::test_remove_and_mask_combined`
- `TestEvidenceRecord::test_to_alpaca_keys`
- `TestEvidenceRecord::test_to_alpaca_output_contains_action_and_result`
- `TestEvidenceRecord::test_to_alpaca_metadata_fields`
- `TestEvidenceRecord::test_to_alpaca_no_context_shows_start`
- `TestEvidenceRecord::test_to_alpaca_context_joined_with_arrow`
- `TestEvidenceRecord::test_to_chat_keys`
- `TestEvidenceRecord::test_to_chat_has_system_user_assistant`
- `TestEvidenceRecord::test_to_chat_assistant_content_contains_action_and_result`
- `TestEvidenceRecord::test_to_chat_system_contains_agent_and_policy`
- `TestEvidenceRecord::test_to_chat_metadata_fields`
- `TestLedgerObserver::test_nonexistent_ledger_returns_empty`
- `TestLedgerObserver::test_empty_ledger_returns_empty`
- `TestLedgerObserver::test_single_allow_entry_extracted`
- `TestLedgerObserver::test_deny_entries_excluded`
- `TestLedgerObserver::test_since_seq_skips_old_entries`
- `TestLedgerObserver::test_context_window_populated`
- `TestLedgerObserver::test_context_window_zero`
- `TestLedgerObserver::test_redaction_applied_to_records`
- `TestLedgerObserver::test_redaction_applied_to_context_before`
- `TestLedgerObserver::test_max_seq_empty_file`
- `TestLedgerObserver::test_max_seq_nonexistent_file`
- `TestLedgerObserver::test_max_seq_returns_highest`
- `TestLedgerObserver::test_malformed_json_lines_skipped`
- `TestLedgerObserver::test_blank_lines_skipped`
- `TestLedgerObserver::test_filter_by_policy_id`
- `TestLedgerObserver::test_observer_ledger_logged_on_extract`
- `TestLedgerObserver::test_observer_ledger_not_called_when_no_records`
- `TestLedgerObserver::test_evidence_record_fields_populated`
- `TestEvidenceExporter::test_export_writes_jsonl`
- `TestEvidenceExporter::test_export_returns_zero_for_empty_result`
- `TestEvidenceExporter::test_export_alpaca_format`
- `TestEvidenceExporter::test_export_chat_format`
- `TestEvidenceExporter::test_export_raw_format`
- `TestEvidenceExporter::test_export_is_append_mode`
- `TestEvidenceExporter::test_export_creates_parent_dirs`
- `TestEvidenceExporter::test_record_count_zero_when_no_file`
- `TestEvidenceExporter::test_record_count_after_export`
- `TestEvidenceExporter::test_observer_ledger_logged_on_export`
- `TestEvidenceExporter::test_since_seq_passed_through`
- `TestTrainingTrigger::test_does_not_fire_below_threshold`
- `TestTrainingTrigger::test_fires_at_threshold`
- `TestTrainingTrigger::test_fires_above_threshold`
- `TestTrainingTrigger::test_accumulates_across_calls`
- `TestTrainingTrigger::test_accumulator_resets_after_fire`
- `TestTrainingTrigger::test_accumulator_property_returns_current`
- `TestTrainingTrigger::test_overflow_fires_once_and_resets`
- `TestTrainingTrigger::test_observer_ledger_logged_on_fire`
- `TestTrainingTrigger::test_observer_ledger_not_called_when_not_fired`
- `TestShadowHook::test_base_class_returns_none`
- `TestShadowHook::test_subclass_can_propose_alternative`
- `TestShadowHook::test_subclass_receives_record_fields`
- `TestObserverIntegration::test_only_allow_decisions_reach_training_data`
- `TestObserverIntegration::test_incremental_export_no_duplicates`
- `TestObserverIntegration::test_context_window_does_not_include_denied_in_output`
- `TestObserverIntegration::test_trigger_fires_after_enough_exports`

### Control Plane (kill switch, pause, quarantine) — `test_enterprise/test_control.py` (59 tests)

- `TestAgentControlRecord::test_is_frozen`
- `TestAgentControlRecord::test_fields_accessible`
- `TestRegistration::test_unregistered_agent_is_active_by_default`
- `TestRegistration::test_register_adds_active_agent`
- `TestRegistration::test_register_noop_if_already_registered`
- `TestPause::test_pause_active_agent`
- `TestPause::test_pause_already_paused_raises`
- `TestPause::test_pause_quarantined_raises`
- `TestPause::test_pause_revoked_raises`
- `TestResume::test_resume_paused_agent`
- `TestResume::test_resume_active_raises`
- `TestResume::test_resume_quarantined_raises`
- `TestResume::test_resume_revoked_raises`
- `TestQuarantine::test_quarantine_active_agent`
- `TestQuarantine::test_quarantine_paused_agent`
- `TestQuarantine::test_quarantine_already_quarantined_raises`
- `TestQuarantine::test_quarantine_revoked_raises`
- `TestRevoke::test_revoke_active_agent`
- `TestRevoke::test_revoke_paused_agent`
- `TestRevoke::test_revoke_quarantined_agent`
- `TestRevoke::test_revoke_already_revoked_raises`
- `TestRevoke::test_revoke_is_terminal`
- `TestKillAll::test_kill_all_revokes_all_active`
- `TestKillAll::test_kill_all_skips_already_revoked`
- `TestKillAll::test_kill_all_empty_returns_empty_list`
- `TestKillAll::test_kill_all_all_already_revoked_returns_empty`
- `TestKillAll::test_kill_all_records_have_correct_command`
- `TestKillAll::test_kill_all_includes_paused_and_quarantined`
- `TestStateQueries::test_get_all_states_snapshot`
- `TestStateQueries::test_get_all_states_is_copy`
- `TestStateQueries::test_is_active_true_for_active`
- `TestStateQueries::test_is_active_false_for_paused`
- `TestStateQueries::test_is_active_false_for_revoked`
- `TestStateQueries::test_is_active_true_for_unknown`
- `TestHistory::test_history_records_transitions`
- `TestHistory::test_history_filtered_by_agent`
- `TestHistory::test_history_filtered_returns_empty_for_unknown`
- `TestHistory::test_history_is_copy`
- `TestHistory::test_history_has_timestamps`
- `TestLedgerIntegration::test_ledger_called_on_pause`
- `TestLedgerIntegration::test_ledger_called_for_each_kill_all_target`
- `TestLedgerIntegration::test_no_ledger_no_error`
- `TestLedgerIntegration::test_ledger_result_field`
- `TestQueueDrain::test_quarantine_drains_pending_for_agent`
- `TestQueueDrain::test_quarantine_operator_id_in_denial`
- `TestQueueDrain::test_kill_all_drains_all_pending`
- `TestQueueDrain::test_already_approved_items_not_re_denied`
- `TestQueueDrain::test_no_queue_quarantine_no_error`
- `TestEnforcerControlGate::test_no_control_plane_normal_enforcement`
- `TestEnforcerControlGate::test_paused_agent_denied_by_enforcer`
- `TestEnforcerControlGate::test_quarantined_agent_denied_by_enforcer`
- `TestEnforcerControlGate::test_revoked_agent_denied_by_enforcer`
- `TestEnforcerControlGate::test_active_agent_passes_step0_to_normal_checks`
- `TestEnforcerControlGate::test_paused_then_resumed_allows_action`
- `TestEnforcerControlGate::test_step0_fires_before_policy_registration_check`
- `TestEnforcerControlGate::test_unknown_agent_treated_as_active_in_control_plane`
- `TestFullWorkflow::test_operator_pause_blocks_then_resume_unblocks`
- `TestFullWorkflow::test_quarantine_blocks_and_drains_queue`
- `TestFullWorkflow::test_kill_all_blocks_entire_mesh`

### Red Team / Adversarial Scenarios — `test_enterprise/test_redteam.py` (59 tests)

- `TestRT01UnknownFields::test_extra_kwargs_in_check_do_not_bypass`
- `TestRT01UnknownFields::test_extra_fields_in_bundle_json_are_ignored`
- `TestRT01UnknownFields::test_bundle_with_injected_admin_field_does_not_escalate`
- `TestRT02SignatureBypass::test_unsigned_bundle_with_require_signature_true_is_denied`
- `TestRT02SignatureBypass::test_tampered_bundle_after_load_is_permanently_denied`
- `TestRT02SignatureBypass::test_sig_field_set_to_empty_string_is_denied`
- `TestRT02SignatureBypass::test_sig_field_set_to_garbage_is_denied`
- `TestRT02SignatureBypass::test_wrong_public_key_denies_valid_sig`
- `TestRT04ClassificationSpoofing::test_cannot_claim_unclassified_if_max_is_unclassified`
- `TestRT04ClassificationSpoofing::test_cannot_claim_cui_above_ceiling`
- `TestRT04ClassificationSpoofing::test_top_secret_blocked_by_secret_ceiling`
- `TestRT04ClassificationSpoofing::test_classification_not_in_request_defaults_to_unclassified`
- `TestRT04ClassificationSpoofing::test_unknown_classification_string_blocked`
- `TestRT05ObserverPoisoning::test_deny_entry_cannot_reach_training_data`
- `TestRT05ObserverPoisoning::test_forged_allow_decision_with_deny_action_type`
- `TestRT05ObserverPoisoning::test_mixed_ledger_only_allow_exported`
- `TestRT05ObserverPoisoning::test_quarantined_decision_excluded`
- `TestRT05ObserverPoisoning::test_observer_filter_with_forged_approval_mode`
- `TestRT07ControlPlaneBypass::test_paused_agent_cannot_act_through_enforcer`
- `TestRT07ControlPlaneBypass::test_quarantined_agent_cannot_act_through_enforcer`
- `TestRT07ControlPlaneBypass::test_revoked_agent_cannot_act_through_enforcer`
- `TestRT07ControlPlaneBypass::test_revoked_agent_cannot_be_reinstated_via_resume`
- `TestRT07ControlPlaneBypass::test_state_dict_mutation_does_not_affect_control_plane`
- `TestRT07ControlPlaneBypass::test_history_list_mutation_does_not_affect_control_plane`
- `TestRT09KillAllRace::test_kill_all_concurrent_with_new_registration`
- `TestRT09KillAllRace::test_concurrent_double_revoke_exactly_one_succeeds`
- `TestRT10QueueDrainBypass::test_approve_after_quarantine_is_blocked`
- `TestRT10QueueDrainBypass::test_concurrent_approve_and_quarantine`
- `TestRT10QueueDrainBypass::test_double_approve_race`
- `TestRT11HashChainForgery::test_tampered_ledger_entry_detected`
- `TestRT11HashChainForgery::test_cng_ledger_tampered_entry_detected`
- `TestRT11HashChainForgery::test_inserted_entry_breaks_chain`
- `TestRT12SeqReplay::test_seq_zero_rejected_by_observer`
- `TestRT12SeqReplay::test_old_seq_skipped_by_since_seq`
- `TestRT13EmptyPolicy::test_empty_allowed_actions_denies_everything`
- `TestRT13EmptyPolicy::test_empty_bundle_denies_unregistered_agent`
- `TestRT13EmptyPolicy::test_special_characters_in_action_do_not_bypass`
- `TestRT14DualRevocation::test_policy_revoked_flag_blocks_agent`
- `TestRT14DualRevocation::test_runtime_revoke_blocks_agent_regardless_of_policy`
- `TestRT14DualRevocation::test_both_revoked_still_blocked`
- `TestRT15ClassificationCeiling::test_classification_matrix[UNCLASSIFIED-UNCLASSIFIED-True]`
- `TestRT15ClassificationCeiling::test_classification_matrix[UNCLASSIFIED-CUI-False]`
- `TestRT15ClassificationCeiling::test_classification_matrix[UNCLASSIFIED-SECRET-False]`
- `TestRT15ClassificationCeiling::test_classification_matrix[UNCLASSIFIED-TOP_SECRET-False]`
- `TestRT15ClassificationCeiling::test_classification_matrix[CUI-UNCLASSIFIED-True]`
- `TestRT15ClassificationCeiling::test_classification_matrix[CUI-CUI-True]`
- `TestRT15ClassificationCeiling::test_classification_matrix[CUI-SECRET-False]`
- `TestRT15ClassificationCeiling::test_classification_matrix[SECRET-SECRET-True]`
- `TestRT15ClassificationCeiling::test_classification_matrix[SECRET-TOP_SECRET-False]`
- `TestRT15ClassificationCeiling::test_classification_matrix[TOP_SECRET-TOP_SECRET-True]`
- `TestRT16RedactionCompleteness::test_redacted_field_absent_from_raw_and_context`
- `TestRT16RedactionCompleteness::test_masked_field_value_replaced_not_present`
- `TestRT17KillAllNoOp::test_kill_all_empty_plane_returns_empty_no_crash`
- `TestRT17KillAllNoOp::test_kill_all_idempotent`
- `TestRT18TrainingTriggerIntegrity::test_accumulated_never_goes_negative`
- `TestRT18TrainingTriggerIntegrity::test_zero_records_does_not_fire`
- `TestRT18TrainingTriggerIntegrity::test_negative_count_handled_safely`
- `TestRT20CngKeyNonExistence::test_load_nonexistent_key_raises`
- `TestRT20CngKeyNonExistence::test_cng_key_exists_returns_false_for_missing`

### Data Classification Labels — `test_enterprise/test_labels.py` (56 tests)

- `TestClassificationEnum::test_enum_values`
- `TestClassificationEnum::test_enum_ordering`
- `TestClassificationEnum::test_enum_by_name`
- `TestClassificationEnum::test_enum_by_value`
- `TestClassificationEnum::test_enum_is_int`
- `TestClassificationEnum::test_enum_members_count`
- `TestRank::test_rank_string_unclassified`
- `TestRank::test_rank_string_top_secret`
- `TestRank::test_rank_enum_value`
- `TestRank::test_rank_case_insensitive`
- `TestRank::test_rank_unknown_string_returns_minus_one`
- `TestRank::test_rank_all_levels_strictly_ordered`
- `TestRank::test_rank_matches_enum_value`
- `TestLe::test_le_same_level`
- `TestLe::test_le_lower_is_dominated`
- `TestLe::test_le_higher_not_dominated`
- `TestLe::test_le_enum_args`
- `TestLe::test_le_mixed_args`
- `TestLabelEnvelope::test_construction_minimal`
- `TestLabelEnvelope::test_construction_with_caveats`
- `TestLabelEnvelope::test_frozen_immutable`
- `TestLabelEnvelope::test_to_dict_keys`
- `TestLabelEnvelope::test_to_dict_classification_is_name`
- `TestLabelEnvelope::test_to_dict_caveats_sorted_list`
- `TestLabelEnvelope::test_from_dict_roundtrip`
- `TestLabelEnvelope::test_from_dict_string_classification`
- `TestLabelEnvelope::test_from_dict_missing_caveats_defaults_empty`
- `TestLabelEnvelope::test_from_classification_factory`
- `TestLabelEnvelope::test_validate_valid_caveats`
- `TestLabelEnvelope::test_validate_invalid_caveat`
- `TestLabelEnvelope::test_validate_empty_caveats_always_valid`
- `TestLabelEnvelope::test_hashable`
- `TestLabelDominance::test_le_reflexive`
- `TestLabelDominance::test_le_lower_classification_no_caveats`
- `TestLabelDominance::test_le_same_classification_subset_caveats`
- `TestLabelDominance::test_le_same_classification_superset_caveats_fails`
- `TestLabelDominance::test_le_lower_classification_superset_caveats_fails`
- `TestLabelDominance::test_le_disjoint_caveats_fails`
- `TestBackwardCompat::test_policy_rank_uses_labels_module`
- `TestBackwardCompat::test_observer_rank_uses_labels_module`
- `TestBackwardCompat::test_classification_levels_from_policy`
- `TestBackwardCompat::test_classification_levels_from_init`
- `TestPolicyEnforcerWithLabel::test_check_with_label_below_ceiling_allowed`
- `TestPolicyEnforcerWithLabel::test_check_with_label_above_ceiling_denied`
- `TestPolicyEnforcerWithLabel::test_check_label_overrides_classification_string`
- `TestPolicyEnforcerWithLabel::test_check_label_invalid_caveats_denied`
- `TestPolicyEnforcerWithLabel::test_check_without_label_string_only_unchanged`
- `TestObserverWithCaveats::test_filter_no_caveat_restriction_passes_any`
- `TestObserverWithCaveats::test_filter_allowed_caveats_subset_passes`
- `TestObserverWithCaveats::test_filter_caveats_not_in_allowed_blocked`
- `TestObserverWithCaveats::test_filter_entry_without_caveats_always_passes_caveat_check`
- `TestObserverWithCaveats::test_observer_never_passes_above_max_classification`
- `TestAllowedCaveats::test_allowed_caveats_is_frozenset`
- `TestAllowedCaveats::test_allowed_caveats_non_empty`
- `TestAllowedCaveats::test_known_caveats_present`
- `TestAllowedCaveats::test_allowed_caveats_immutable`

### Policy Enforcer — `test_enterprise/test_policy.py` (48 tests)

- `TestAgentPolicy::test_from_dict_defaults`
- `TestAgentPolicy::test_from_dict_full`
- `TestPolicyBundle::test_from_dict_parses_agents`
- `TestPolicyBundle::test_policy_id_preserved`
- `TestPolicyBundle::test_to_signable_bytes_excludes_sig_and_pub`
- `TestPolicyBundle::test_to_signable_bytes_is_deterministic`
- `TestPolicyBundle::test_to_dict_roundtrip`
- `TestPolicyBundle::test_from_file_roundtrip`
- `TestPolicyBundle::test_is_time_valid_current`
- `TestPolicyBundle::test_is_time_valid_before_valid_from`
- `TestPolicyBundle::test_is_time_valid_after_valid_until`
- `TestPolicyBundle::test_is_time_valid_no_expiry`
- `TestPolicyDecision::test_to_ledger_metadata_allowed`
- `TestPolicyDecision::test_to_ledger_metadata_denied`
- `TestEnforcerDenyPaths::test_unknown_agent_denied`
- `TestEnforcerDenyPaths::test_revoked_agent_quarantined`
- `TestEnforcerDenyPaths::test_expired_policy_denied`
- `TestEnforcerDenyPaths::test_disallowed_target_denied`
- `TestEnforcerDenyPaths::test_blocked_app_denied`
- `TestEnforcerDenyPaths::test_app_not_in_allowed_list_denied`
- `TestEnforcerDenyPaths::test_unlisted_action_denied`
- `TestEnforcerDenyPaths::test_classification_ceiling_exceeded`
- `TestEnforcerDenyPaths::test_empty_allowed_actions_denies_everything`
- `TestEnforcerAllowPaths::test_basic_allow`
- `TestEnforcerAllowPaths::test_allowed_with_matching_classification`
- `TestEnforcerAllowPaths::test_no_target_restriction_when_allowed_targets_empty`
- `TestEnforcerAllowPaths::test_all_apps_allowed_when_allowed_apps_empty`
- `TestEnforcerAllowPaths::test_approval_gate_flagged_but_allowed`
- `TestEnforcerAllowPaths::test_policy_id_propagated`
- `TestEnforcerAllowPaths::test_decision_has_agent_and_action`
- `TestSignatureEnforcement::test_require_signature_true_no_sig_denies`
- `TestSignatureEnforcement::test_require_signature_false_skips_check`
- `TestOperatorQueue::test_submit_returns_id`
- `TestOperatorQueue::test_status_pending_after_submit`
- `TestOperatorQueue::test_approve_changes_status`
- `TestOperatorQueue::test_deny_changes_status`
- `TestOperatorQueue::test_approve_sets_operator_id`
- `TestOperatorQueue::test_approve_twice_returns_false`
- `TestOperatorQueue::test_deny_already_approved_returns_false`
- `TestOperatorQueue::test_nonexistent_id_returns_not_found`
- `TestOperatorQueue::test_get_pending_returns_only_pending`
- `TestOperatorQueue::test_len`
- `TestOperatorQueue::test_context_stored`
- `TestOperatorQueue::test_purge_expired_removes_decided`
- `TestOperatorQueue::test_purge_does_not_remove_pending`
- `TestFullWorkflow::test_allowed_action_produces_correct_metadata`
- `TestFullWorkflow::test_denied_action_produces_deny_metadata`
- `TestFullWorkflow::test_requires_approval_workflow`

### Approval Audit Binding — `test_approval_audit.py` (23 tests)

- `test_required_sink_cannot_be_omitted`
- `test_unverified_decision_writer_cannot_approve`
- `test_audit_failure_leaves_transition_non_authorizing_until_reconciled`
- `test_submit_failure_exposes_recoverable_approval_identifier`
- `test_deny_transition_is_recorded_before_state_changes`
- `test_raw_context_is_not_written_to_audit_event`
- `test_concurrent_decision_race_records_exactly_one_approval`
- `test_append_before_receipt_marker_is_reconciled_without_duplicate`
- `test_tampered_pending_outbox_cannot_be_reconciled`
- `test_consume_audit_failure_never_returns_authority`
- `test_consumed_binding_rechecks_signed_ledger_receipt`
- `test_consumed_binding_fails_when_signed_ledger_chain_is_altered`
- `test_expiry_is_audited_before_capability_becomes_expired`
- `test_matching_receipt_from_unverifiable_sink_never_clears_audit_pending`
- `test_state_changed_during_external_append_is_revalidated_under_write_lock`
- `test_direct_sqlite_approved_forgery_cannot_create_valid_lineage`
- `test_decision_envelope_is_bound_and_raw_proof_is_not_retained`
- `test_decision_verifier_receives_the_complete_canonical_binding`
- `test_backward_clock_skew_fails_closed`
- `test_purge_uses_terminal_and_delivery_time_not_submission_time`
- `test_legacy_schema_migrates_to_closed_sets_and_foreign_keys`
- `test_system_safety_denial_is_not_human_attribution_or_approval_bypass`
- `test_reused_decision_nonce_fails_closed`

### Identity Gate — `test_identity_gate.py` (46 tests)

- `TestBPCCrypto::test_b64url_roundtrip`
- `TestBPCCrypto::test_canonicalize_sorted_keys`
- `TestBPCCrypto::test_canonicalize_rejects_nested`
- `TestBPCCrypto::test_canonicalize_rejects_forbidden_key`
- `TestBPCCrypto::test_body_hash_deterministic`
- `TestBPCCrypto::test_hash_secret_produces_b64url`
- `TestBPCCrypto::test_hmac_derive_deterministic`
- `TestBPCCrypto::test_sign_verify_roundtrip`
- `TestBPCCrypto::test_sign_verify_tampered_payload`
- `TestBPCCrypto::test_p256_derivation_is_deterministic`
- `TestBPCCrypto::test_different_agents_get_different_keys`
- `TestBPCCrypto::test_constant_time_equal`
- `TestTSKClient::test_validate_hex_secret_valid`
- `TestTSKClient::test_validate_hex_secret_too_short`
- `TestTSKClient::test_validate_hex_secret_non_hex`
- `TestTSKClient::test_derive_static_deterministic`
- `TestTSKClient::test_derive_totp_changes_with_window`
- `TestTSKClient::test_derive_hotp_uses_counter`
- `TestTSKClient::test_segment_length_enforced`
- `TestTSKClient::test_generate_tsk_key_has_checksum`
- `TestTSKClient::test_generate_tsk_key_deterministic_same_window`
- `TestTSKClient::test_parse_provision_payload`
- `TestUltraGate::test_build_injection_request_structure`
- `TestUltraGate::test_self_verify_passes`
- `TestUltraGate::test_verify_local_uses_protocol_checksum_length`
- `TestUltraGate::test_self_verify_fails_on_tampered_text`
- `TestUltraGate::test_authorize_injection_success`
- `TestUltraGate::test_not_bootstrapped_raises`
- `TestUltraGate::test_status_dict`
- `TestIdentityGateMode::test_default_mode_is_bypass`
- `TestIdentityGateMode::test_audit_mode`
- `TestIdentityGateMode::test_enforce_mode`
- `TestIdentityGateMode::test_invalid_mode_falls_back_to_bypass`
- `TestIdentityGateMode::test_mutex_downgrades_enforce_to_audit`
- `TestIdentityGateMode::test_bypass_mode_skips_gate`
- `TestIdentityGateMode::test_enforce_mode_blocks_when_gate_fails`
- `TestIdentityGateMode::test_audit_mode_proceeds_on_failure`
- `TestDegradationCascade::test_no_gate_skips_level0`
- `TestDegradationCascade::test_enforce_stops_at_level2`
- `TestDegradationCascade::test_audit_can_go_to_level4`
- `TestKeyRecovery::test_recovery_pub_write_read`
- `TestKeyRecovery::test_recovery_pub_without_token_is_rejected`
- `TestKeyRecovery::test_recovery_pub_expired`
- `TestKeyRecovery::test_recovery_pub_no_file`
- `TestSCRequireUltra::test_require_ultra_without_gate_raises`
- `TestSCRequireUltra::test_require_ultra_with_gate_passes`

### CNG Identity (Windows-only — skipped on Linux) — `test_enterprise/test_identity_cng.py` (43 tests)

- `TestInit::test_creates_pub_file`
- `TestInit::test_creates_algo_file`
- `TestInit::test_agent_id_format`
- `TestInit::test_agent_id_derived_from_sha384_of_public_key`
- `TestInit::test_public_key_bytes_length`
- `TestInit::test_pub_file_hex_matches_public_key`
- `TestInit::test_raises_if_already_exists`
- `TestInit::test_overwrite_replaces_key`
- `TestInit::test_algo_id_property`
- `TestLoad::test_load_restores_same_agent_id`
- `TestLoad::test_load_restores_same_public_key`
- `TestLoad::test_load_raises_if_not_found`
- `TestLoad::test_signatures_match_across_load`
- `TestExists::test_false_before_init`
- `TestExists::test_true_after_init`
- `TestSignVerify::test_sign_returns_96_bytes`
- `TestSignVerify::test_valid_signature_verifies`
- `TestSignVerify::test_wrong_data_fails_verify`
- `TestSignVerify::test_wrong_key_fails_verify`
- `TestSignVerify::test_garbage_signature_fails`
- `TestSignVerify::test_verify_never_raises`
- `TestSignVerify::test_different_messages_produce_different_sigs`
- `TestCngLedgerLog::test_creates_log_file`
- `TestCngLedgerLog::test_entry_has_required_fields`
- `TestCngLedgerLog::test_algo_field_is_correct`
- `TestCngLedgerLog::test_seq_increments`
- `TestCngLedgerLog::test_first_entry_uses_genesis_hash`
- `TestCngLedgerLog::test_genesis_hash_is_96_zeros`
- `TestCngLedgerLog::test_second_entry_prev_hash_matches_first`
- `TestCngLedgerLog::test_agent_id_matches_identity`
- `TestCngLedgerLog::test_sig_is_96_byte_hex_string`
- `TestCngLedgerLog::test_metadata_merged_into_entry`
- `TestCngLedgerLog::test_appends_to_file`
- `TestCngLedgerVerify::test_empty_ledger_is_valid`
- `TestCngLedgerVerify::test_single_entry_is_valid`
- `TestCngLedgerVerify::test_many_entries_all_valid`
- `TestCngLedgerVerify::test_tampered_entry_detected`
- `TestCngLedgerVerify::test_deleted_entry_detected`
- `TestCngLedgerVerify::test_sig_field_tampered_detected`
- `TestCngLedgerContinuity::test_new_instance_continues_chain`
- `TestCngLedgerContinuity::test_seq_continues_from_last`
- `TestHashChainAlgorithm::test_prev_hash_is_96_hex_chars`
- `TestHashChainAlgorithm::test_prev_hash_is_not_sha256`

### Penetration Test — Injection — `test_enterprise/test_pentest_injection.py` (43 tests)

- `TestWfpProcessInjection::test_process_name_does_not_inject_script_commands[safe-0]`
- `TestWfpProcessInjection::test_process_name_does_not_inject_script_commands[safe-1]`
- `TestWfpProcessInjection::test_process_name_does_not_inject_script_commands[safe-2]`
- `TestWfpProcessInjection::test_process_name_does_not_inject_script_commands[safe-3]`
- `TestWfpProcessInjection::test_process_name_does_not_inject_script_commands[safe-4]`
- `TestWfpProcessInjection::test_process_name_does_not_inject_script_commands[safe-5]`
- `TestWfpProcessInjection::test_process_name_does_not_inject_script_commands[safe-6]`
- `TestWfpProcessInjection::test_process_name_does_not_inject_script_commands[safe-7]`
- `TestWfpProcessInjection::test_generated_script_is_syntactically_bounded[safe-proc-0]`
- `TestWfpProcessInjection::test_generated_script_is_syntactically_bounded[safe-proc-1]`
- `TestWfpProcessInjection::test_generated_script_is_syntactically_bounded[safe-proc-2]`
- `TestWfpProcessInjection::test_generated_script_is_syntactically_bounded[safe-proc-3]`
- `TestWfpProcessInjection::test_generated_script_is_syntactically_bounded[safe-proc-4]`
- `TestWfpProcessInjection::test_generated_script_is_syntactically_bounded[safe-proc-5]`
- `TestWfpProcessInjection::test_generated_script_is_syntactically_bounded[safe-proc-6]`
- `TestWfpProcessInjection::test_generated_script_is_syntactically_bounded[safe-proc-7]`
- `TestWfpProcessInjection::test_newline_injection_is_rejected_at_construction[newline-LF]`
- `TestWfpProcessInjection::test_newline_injection_is_rejected_at_construction[newline-CRLF]`
- `TestWfpAllowEntryInjection::test_semicolon_in_host_rejected`
- `TestWfpAllowEntryInjection::test_dollar_in_host_rejected`
- `TestWfpAllowEntryInjection::test_backtick_in_host_rejected`
- `TestWfpAllowEntryInjection::test_newline_in_host_rejected`
- `TestWfpAllowEntryInjection::test_pipe_in_host_rejected`
- `TestWfpAllowEntryInjection::test_double_quote_in_host_rejected`
- `TestWfpAllowEntryInjection::test_ampersand_in_host_rejected`
- `TestWfpAllowEntryInjection::test_valid_host_passes`
- `TestWfpAllowEntryInjection::test_valid_cidr_passes`
- `TestWfpAllowEntryInjection::test_valid_ipv6_passes`
- `TestWfpScriptOutputSafety::test_program_arg_uses_single_quotes`
- `TestWfpScriptOutputSafety::test_dollar_subexpression_does_not_expand`
- `TestWfpScriptOutputSafety::test_backtick_injection_is_inert_in_single_quotes`
- `TestWfpScriptOutputSafety::test_single_quote_in_process_name_is_escaped`
- `TestPathTraversalDPAPI::test_traversal_data_dir_stays_within_parent`
- `TestPathTraversalDPAPI::test_traversal_with_dotdot_agent_name`
- `TestPathTraversalDPAPI::test_absolute_path_override`
- `TestPathTraversalCNG::test_cng_traversal_agent_name`
- `TestTrainingTriggerInjection::test_popen_uses_list_not_shell`
- `TestTrainingTriggerInjection::test_popen_called_without_shell_kwarg`
- `TestTrainingTriggerInjection::test_nonexistent_binary_raises`
- `TestTrainingTriggerInjection::test_empty_command_raises`
- `TestTrainingTriggerInjection::test_trigger_does_not_fire_below_threshold`
- `TestTrainingTriggerInjection::test_trigger_resets_after_fire`
- `TestTrainingTriggerInjection::test_trigger_logs_to_observer_ledger`

### Classified Mode — `test_enterprise/test_classified_mode.py` (40 tests)

- `TestClassifiedModeProfile::test_construction_minimal`
- `TestClassifiedModeProfile::test_frozen_immutable`
- `TestClassifiedModeProfile::test_validate_valid_profile`
- `TestClassifiedModeProfile::test_validate_invalid_caveats`
- `TestClassifiedModeProfile::test_to_dict_keys`
- `TestClassifiedModeProfile::test_from_dict_roundtrip`
- `TestClassifiedModeProfile::test_from_dict_unknown_classification_defaults_unclassified`
- `TestClassifiedModeProfile::test_to_policy_constraints_keys`
- `TestClassifiedModeProfile::test_save_and_from_file`
- `TestClassifiedModeProfile::test_from_file_missing_sig_raises_when_verify_true`
- `TestBaselines::test_secret_baseline_is_valid`
- `TestBaselines::test_secret_baseline_ceiling`
- `TestBaselines::test_secret_baseline_no_egress`
- `TestBaselines::test_secret_baseline_no_export`
- `TestBaselines::test_secret_baseline_requires_cng`
- `TestBaselines::test_cui_baseline_is_valid`
- `TestBaselines::test_cui_baseline_ceiling`
- `TestBaselines::test_cui_baseline_allows_egress`
- `TestBaselines::test_cui_baseline_allows_export`
- `TestEgressGuard::test_check_denied_when_egress_disabled`
- `TestEgressGuard::test_check_allowed_when_egress_enabled`
- `TestEgressGuard::test_wrap_returns_none_when_denied`
- `TestEgressGuard::test_wrap_calls_fn_when_allowed`
- `TestEgressGuard::test_check_logs_to_ledger_denied`
- `TestEgressGuard::test_check_logs_to_ledger_allowed`
- `TestEgressGuard::test_no_ledger_no_error`
- `TestExportGuard::test_can_export_denied_when_export_disabled`
- `TestExportGuard::test_can_export_allowed_within_ceiling`
- `TestExportGuard::test_can_export_denied_above_ceiling`
- `TestExportGuard::test_can_export_denied_caveat_not_allowed`
- `TestExportGuard::test_can_export_allowed_subset_caveats`
- `TestExportGuard::test_check_and_log_logs_denial`
- `TestExportGuard::test_check_and_log_logs_allowance`
- `TestPolicyEnforcerWithProfile::test_profile_ceiling_denies_above_max`
- `TestPolicyEnforcerWithProfile::test_profile_ceiling_allows_at_max`
- `TestPolicyEnforcerWithProfile::test_profile_dpapi_rejected_when_cng_required`
- `TestPolicyEnforcerWithProfile::test_profile_cng_identity_accepted`
- `TestPolicyEnforcerWithProfile::test_no_profile_unchanged_behavior`
- `TestClassifiedModeEndToEnd::test_classified_mode_full_scenario`
- `TestClassifiedModeEndToEnd::test_cui_baseline_full_scenario`

### WFP Network Policy — `test_wfp_policy.py` (36 tests)

- `TestAllowEntryParse::test_ip_only`
- `TestAllowEntryParse::test_ip_port`
- `TestAllowEntryParse::test_ip_port_proto`
- `TestAllowEntryParse::test_cidr`
- `TestAllowEntryParse::test_hostname`
- `TestAllowEntryParse::test_any_proto`
- `TestAllowEntryParse::test_any_proto_with_port`
- `TestAllowEntryParse::test_invalid_port_rejected`
- `TestAllowEntryParse::test_invalid_host_rejected`
- `TestAllowEntryParse::test_loopback`
- `TestAllowEntryParse::test_ipv6_loopback`
- `TestWfpProfile::test_from_dict_minimal`
- `TestWfpProfile::test_from_dict_full`
- `TestWfpProfile::test_from_json`
- `TestBuiltinProfiles::test_all_profiles_parseable`
- `TestBuiltinProfiles::test_mode_c_allows_only_loopback`
- `TestBuiltinProfiles::test_mode_c_strict_is_more_restrictive_than_mode_c`
- `TestBuiltinProfiles::test_mode_a_allows_all`
- `TestGeneratePowershell::test_block_rule_present`
- `TestGeneratePowershell::test_allow_rule_present`
- `TestGeneratePowershell::test_remove_flag_present`
- `TestGeneratePowershell::test_verify_flag_present`
- `TestGeneratePowershell::test_process_name_embedded`
- `TestGeneratePowershell::test_requires_administrator`
- `TestGeneratePowershell::test_multiple_allow_rules`
- `TestGeneratePowershell::test_mode_c_script_is_loopback_only`
- `TestGeneratePowershell::test_no_arbitrary_code_in_output`
- `TestGeneratePowershell::test_output_is_utf8_decodable`
- `TestCLI::test_list_profiles`
- `TestCLI::test_builtin_profile_to_stdout`
- `TestCLI::test_custom_allow_to_stdout`
- `TestCLI::test_output_to_file`
- `TestCLI::test_no_args_errors`
- `TestCLI::test_invalid_allow_errors`
- `TestCLI::test_missing_config_errors`
- `TestCLI::test_mode_c_strict_profile`

### Agent Registry — `test_enterprise/test_registry.py` (34 tests)

- `TestBirthTag::test_to_dict_shape`
- `TestBirthTag::test_age_seconds`
- `TestBirthTag::test_is_alive_recent_heartbeat`
- `TestBirthTag::test_is_alive_stale_heartbeat`
- `TestBirthTag::test_is_alive_custom_threshold`
- `TestBirthTag::test_seconds_since_heartbeat`
- `TestAgentProps::test_set_prop_calls_setpropw`
- `TestAgentProps::test_get_prop_returns_empty_when_absent`
- `TestAgentProps::test_get_prop_resolves_atom`
- `TestStampBirthTag::test_returns_birth_tag`
- `TestStampBirthTag::test_stamps_all_required_props`
- `TestStampBirthTag::test_stamp_includes_pid_and_ctime`
- `TestStampBirthTag::test_session_prop_only_when_provided`
- `TestUpdateHeartbeat::test_returns_false_if_not_stamped`
- `TestUpdateHeartbeat::test_updates_hb_if_stamped`
- `TestReadBirthTag::test_returns_none_if_no_scid`
- `TestReadBirthTag::test_returns_birth_tag_when_stamped`
- `TestVerifyTag::test_fails_if_window_dead`
- `TestVerifyTag::test_fails_if_no_pid`
- `TestVerifyTag::test_fails_if_pid_mismatch`
- `TestVerifyTag::test_fails_if_ctime_mismatch`
- `TestVerifyTag::test_passes_when_all_match`
- `TestVerifyTag::test_passes_without_ctime_if_zero`
- `TestDiscoverMesh::test_empty_when_no_stamped_windows`
- `TestDiscoverMesh::test_heartbeat_age_filters_stale`
- `TestDiscoverMesh::test_find_agent_returns_none_when_absent`
- `TestDiscoverMesh::test_find_agent_returns_match`
- `TestSendData::test_send_data_calls_sendmessagew`
- `TestSendData::test_send_data_returns_false_on_failure`
- `TestNamedEvents::test_signal_ready_creates_and_sets`
- `TestNamedEvents::test_signal_ready_returns_false_on_create_failure`
- `TestNamedEvents::test_wait_for_returns_true_when_signaled`
- `TestNamedEvents::test_wait_for_returns_false_on_timeout`
- `TestHeartbeatDaemon::test_daemon_calls_update_heartbeat`

### AgentLedger / Hash Chain — `test_enterprise/test_ledger.py` (45 tests)

- `TestLog::test_creates_log_file`
- `TestLog::test_entry_has_required_fields`
- `TestLog::test_seq_increments`
- `TestLog::test_partial_append_failure_restores_tail_for_retry_and_restart`
- `TestLog::test_fsync_failure_does_not_publish_sequence`
- `TestLog::test_nested_index_rejects_wrong_metadata_type`
- `TestLog::test_first_entry_uses_genesis_hash`
- `TestLog::test_second_entry_prev_hash_matches_first`
- `TestLog::test_agent_id_matches_identity`
- `TestLog::test_sig_is_hex_string`
- `TestLog::test_metadata_merged_into_entry`
- `TestLog::test_appends_to_file`
- `TestVerify::test_empty_ledger_is_valid`
- `TestVerify::test_single_entry_is_valid`
- `TestVerify::test_many_entries_all_valid`
- `TestVerify::test_tampered_entry_detected`
- `TestVerify::test_deleted_entry_detected`
- `TestVerify::test_sig_field_tampered_detected`
- `TestVerify::test_verify_returns_count`
- `TestContinuity::test_new_instance_continues_chain`
- `TestContinuity::test_seq_continues_from_last`
- `TestTailCount::test_tail_empty_returns_empty`
- `TestTailCount::test_tail_returns_n_entries`
- `TestTailCount::test_tail_returns_last_entries`
- `TestTailCount::test_entry_count_zero_when_empty`
- `TestTailCount::test_entry_count_correct`
- `TestThreadSafeAgentLedger::test_is_subclass_of_agent_ledger`
- `TestThreadSafeAgentLedger::test_single_write`
- `TestThreadSafeAgentLedger::test_concurrent_writes_chain_intact`
- `TestThreadSafeAgentLedger::test_concurrent_writes_seq_unique`
- `TestThreadSafeAgentLedger::test_thread_safe_verify`
- `TestThreadSafeAgentLedger::test_thread_safe_tail`
- `TestThreadSafeAgentLedger::test_thread_safe_entry_count`

### Handshake Protocol — `test_enterprise/test_handshake.py` (28 tests)

- `test_signed_bytes_deterministic`
- `test_signed_bytes_changes_with_nonce`
- `test_signed_bytes_changes_with_hwnd`
- `test_challenge_payload_fields`
- `TestPeerBackoff::test_new_agent_not_blocked`
- `TestPeerBackoff::test_after_failure_agent_is_blocked`
- `TestPeerBackoff::test_clear_unblocks_agent`
- `TestPeerBackoff::test_expired_failure_not_blocked`
- `TestPeerBackoff::test_blocked_count`
- `TestPeerBackoff::test_different_agents_independent`
- `TestHandshakeResponder::test_handle_challenge_sends_response`
- `TestHandshakeResponder::test_handle_challenge_verifiable_signature`
- `TestHandshakeResponder::test_malformed_challenge_dropped`
- `TestHandshakeInitiator::test_successful_handshake`
- `TestHandshakeInitiator::test_fails_on_nonce_mismatch`
- `TestHandshakeInitiator::test_fails_on_corrupted_signature`
- `TestHandshakeInitiator::test_fails_on_timeout`
- `TestHandshakeInitiator::test_fails_if_send_data_fails`
- `TestHandshakeInitiator::test_birth_tag_cross_check_passes_with_valid_sig`
- `TestHandshakeInitiator::test_birth_tag_cross_check_fails_with_wrong_key`
- `TestDiscoverHandshakePeers::test_returns_empty_when_not_v2`
- `TestDiscoverHandshakePeers::test_returns_empty_when_no_candidates`
- `TestDiscoverHandshakePeers::test_filters_own_hwnd`
- `TestDiscoverHandshakePeers::test_filters_backoff_blocked_peers`
- `TestDiscoverHandshakePeers::test_successful_peer_returned`
- `test_handshake_v2_enabled_false_by_default`
- `test_handshake_v2_enabled_true_when_set`
- `test_handshake_v2_enabled_case_insensitive`

### Cryptographic Primitives — `test_enterprise/test_crypto.py` (27 tests)

- `TestSha384::test_empty_string_produces_known_vector`
- `TestSha384::test_output_is_48_bytes`
- `TestSha384::test_different_inputs_produce_different_hashes`
- `TestSha384::test_same_input_produces_same_hash`
- `TestSha384::test_large_input`
- `TestKeyLifecycle::test_create_returns_96_byte_public_key`
- `TestKeyLifecycle::test_key_exists_after_create`
- `TestKeyLifecycle::test_key_not_exists_before_create`
- `TestKeyLifecycle::test_create_twice_raises`
- `TestKeyLifecycle::test_create_overwrite_replaces_key`
- `TestKeyLifecycle::test_load_returns_same_public_key`
- `TestKeyLifecycle::test_load_nonexistent_raises_file_not_found`
- `TestKeyLifecycle::test_delete_key_removes_it`
- `TestKeyLifecycle::test_delete_nonexistent_key_returns_false`
- `TestKeyLifecycle::test_algo_id_is_correct`
- `TestKeyLifecycle::test_key_name_property`
- `TestKeyLifecycle::test_context_manager_closes_handles`
- `TestSignVerify::test_sign_returns_96_bytes`
- `TestSignVerify::test_valid_signature_verifies`
- `TestSignVerify::test_tampered_data_fails_verify`
- `TestSignVerify::test_wrong_public_key_fails_verify`
- `TestSignVerify::test_zero_signature_fails_verify`
- `TestSignVerify::test_truncated_signature_fails_verify`
- `TestSignVerify::test_verify_with_garbage_never_raises`
- `TestSignVerify::test_different_messages_produce_different_sigs`
- `TestSignVerify::test_load_and_sign_matches_create_pubkey`
- `TestSignVerify::test_sign_empty_bytes`

### Transport Layer — `test_enterprise/test_transport.py` (24 tests)

- `TestCopyDataStruct::test_fields_present`
- `TestCopyDataStruct::test_size_reasonable`
- `TestRegister::test_register_stores_callback`
- `TestRegister::test_register_multiple_for_same_type`
- `TestRegister::test_register_different_types_isolated`
- `TestHandleCopydata::test_dispatches_to_registered_callback`
- `TestHandleCopydata::test_dispatches_by_data_type`
- `TestHandleCopydata::test_no_callback_for_type_is_silent`
- `TestHandleCopydata::test_bad_lparam_does_not_raise`
- `TestHandleCopydata::test_invalid_json_does_not_raise`
- `TestHandleCopydata::test_callback_exception_does_not_crash_listener`
- `TestHandleCopydata::test_multiple_callbacks_all_invoked`
- `TestStartStop::test_start_sets_hwnd`
- `TestStartStop::test_start_window_create_failure_raises`
- `TestStartStop::test_stop_posts_wm_quit`
- `TestStartStop::test_stop_clears_hwnd`
- `TestStartStop::test_stop_is_idempotent`
- `TestStartStop::test_double_start_is_idempotent`
- `TestHwndProperty::test_hwnd_none_before_start`
- `TestHwndProperty::test_hwnd_set_during_run`
- `TestUniqueClassName::test_class_names_are_unique`
- `TestUniqueClassName::test_class_name_contains_prefix`
- `TestConstants::test_wm_copydata_value`
- `TestConstants::test_wm_quit_value`

### Dependency Integrity — `test_enterprise/test_dependency_integrity.py` (23 tests)

- `TestGitDependencyPinning::test_all_git_deps_pinned_to_commit_hash`
- `TestInstallHookSafety::test_selfconnect_setup_has_no_dangerous_hooks`
- `TestInstallHookSafety::test_cryptography_no_unexpected_build_hooks`
- `TestUnexpectedSubdependencies::test_no_known_malicious_packages_installed`
- `TestUnexpectedSubdependencies::test_no_known_silentsync_rat_packages`
- `TestUnexpectedSubdependencies::test_selfconnect_declared_deps_match_installed`
- `TestModuleShadowAttack::test_enterprise_resolves_to_local_module`
- `TestModuleShadowAttack::test_no_pypi_package_named_enterprise`
- `TestModuleShadowAttack::test_crypto_module_resolves_safely`
- `TestModuleShadowAttack::test_generic_module_names_not_in_site_packages_root[ledger]`
- `TestModuleShadowAttack::test_generic_module_names_not_in_site_packages_root[policy]`
- `TestModuleShadowAttack::test_generic_module_names_not_in_site_packages_root[observer]`
- `TestModuleShadowAttack::test_generic_module_names_not_in_site_packages_root[transport]`
- `TestModuleShadowAttack::test_generic_module_names_not_in_site_packages_root[labels]`
- `TestModuleShadowAttack::test_generic_module_names_not_in_site_packages_root[control]`
- `TestModuleShadowAttack::test_generic_module_names_not_in_site_packages_root[registry]`
- `TestMcpToolMetadataInjection::test_scanner_detects_authority_injection`
- `TestMcpToolMetadataInjection::test_scanner_passes_benign_description`
- `TestMcpToolMetadataInjection::test_scanner_detects_credential_exfiltration`
- `TestMcpToolMetadataInjection::test_scanner_detects_role_override`
- `TestMcpToolMetadataInjection::test_scanner_detects_ignore_previous`
- `TestMcpToolMetadataInjection::test_scanner_is_importable_as_utility`
- `TestFutureProofIocRegistry::test_ioc_registry_is_checked`

### Agent Identity (Ed25519) — `test_enterprise/test_identity.py` (22 tests)

- `TestInit::test_creates_files`
- `TestInit::test_agent_id_format`
- `TestInit::test_agent_id_derived_from_public_key`
- `TestInit::test_public_key_bytes_length`
- `TestInit::test_raises_if_already_exists`
- `TestInit::test_overwrite_replaces_key`
- `TestInit::test_pub_file_contains_hex`
- `TestLoad::test_load_restores_same_agent_id`
- `TestLoad::test_load_restores_same_public_key`
- `TestLoad::test_load_raises_if_not_found`
- `TestLoad::test_signatures_match_across_load`
- `TestExists::test_false_before_init`
- `TestExists::test_true_after_init`
- `TestSignVerify::test_sign_returns_64_bytes`
- `TestSignVerify::test_valid_signature_verifies`
- `TestSignVerify::test_wrong_data_fails_verify`
- `TestSignVerify::test_wrong_key_fails_verify`
- `TestSignVerify::test_truncated_signature_fails`
- `TestSignVerify::test_garbage_signature_fails`
- `TestSignVerify::test_verify_never_raises`
- `TestSignVerify::test_different_messages_produce_different_sigs`
- `TestRepr::test_repr_contains_agent_id`

### Coverage Gap Tests — `test_enterprise/test_coverage_gaps.py` (21 tests)

- `TestExportGuardAllowExport::test_allow_export_true_label_within_ceiling`
- `TestExportGuardAllowExport::test_allow_export_true_label_at_ceiling`
- `TestExportGuardAllowExport::test_allow_export_true_label_above_ceiling`
- `TestExportGuardDenyExport::test_deny_export_false_blocks_everything`
- `TestExportGuardDenyExport::test_deny_export_with_matching_caveats`
- `TestExportGuardCaveats::test_label_caveats_not_subset_of_profile`
- `TestExportGuardCaveats::test_label_caveats_subset_of_profile`
- `TestExportGuardCheckAndLog::test_check_and_log_allowed`
- `TestExportGuardCheckAndLog::test_check_and_log_denied`
- `TestExportGuardCheckAndLog::test_check_and_log_no_ledger`
- `TestExportGuardProperties::test_ceiling_property`
- `TestExportGuardProperties::test_profile_property`
- `TestExportGuardProperties::test_deny_reason_export_disabled`
- `TestExportGuardProperties::test_deny_reason_classification_exceeded`
- `TestExportGuardProperties::test_deny_reason_bad_caveats`
- `TestProfileFromFileSignature::test_from_file_verify_signature_success`
- `TestProfileFromFileSignature::test_from_file_tampered_raises`
- `TestProfileFromFileSignature::test_from_file_no_signature_raises`
- `TestProfileFromFileSignature::test_from_file_skip_verification`
- `TestProfileFromFileSignature::test_from_file_no_public_key_raises`
- `TestProfileFromFileSignature::test_from_file_embedded_pub_key_verification`

### E2E Ultra Gate (21 skipped without live server) — `test_e2e_ultra_gate.py` (20 tests)

- `TestUltraGateBootstrap::test_bootstrap_assigns_pair_id`
- `TestUltraGateBootstrap::test_bootstrap_assigns_tsk_state`
- `TestUltraGateBootstrap::test_bootstrap_is_idempotent`
- `TestUltraGateBootstrap::test_server_status_shows_pair_registered`
- `TestBuildInjectionRequest::test_headers_contain_required_keys`
- `TestBuildInjectionRequest::test_pair_id_matches_bootstrap`
- `TestBuildInjectionRequest::test_tsk_key_has_checksum`
- `TestBuildInjectionRequest::test_signed_data_is_valid_base64url`
- `TestAuthorizeInjection::test_authorize_injection_succeeds_for_valid_text`
- `TestAuthorizeInjection::test_authorize_injection_succeeds_for_empty_text`
- `TestAuthorizeInjection::test_authorize_injection_succeeds_for_unicode`
- `TestAuthorizeInjection::test_authorize_injection_raises_before_bootstrap`
- `TestVerifyServer::test_valid_request_passes_server_verification`
- `TestVerifyServer::test_multiple_sequential_requests_pass`
- `TestVerifyServer::test_tampered_body_hash_is_rejected`
- `TestVerifyServer::test_wrong_pair_id_is_rejected`
- `TestVerifyServer::test_missing_tsk_key_is_rejected`
- `TestVerifyServer::test_truncated_signature_is_rejected`
- `TestFullE2EFlow::test_full_flow_two_agents_cross_verify`
- `TestFullE2EFlow::test_full_flow_high_frequency`

### Adversarial AI Scenarios — `test_enterprise/test_adversarial_ai.py` (17 tests)

- `TestTrainingDataPoisoningAttack::test_raw_modification_detected_by_verify`
- `TestTrainingDataPoisoningAttack::test_observer_reads_without_verify_documents_gap`
- `TestTrainingDataPoisoningAttack::test_policy_id_allowlist_blocks_injected_training_entry`
- `TestTrainingDataPoisoningAttack::test_default_observer_passes_injected_entry_documents_risk`
- `TestClassificationCeilingBypass::test_ceiling_enforced_regardless_of_signed_policy_content`
- `TestClassificationCeilingBypass::test_within_ceiling_policy_is_allowed`
- `TestLabelEnvelopeImmutability::test_label_envelope_is_frozen`
- `TestLabelEnvelopeImmutability::test_observer_max_classification_blocks_secret_entries`
- `TestControlPlaneRaceConditions::test_revoked_agents_not_active_after_kill_all`
- `TestControlPlaneRaceConditions::test_kill_all_concurrent_registration_no_survivors`
- `TestControlPlaneRaceConditions::test_revoked_agent_re_register_is_noop`
- `TestControlPlaneRaceConditions::test_paused_agent_re_register_is_noop`
- `TestControlPlaneRaceConditions::test_quarantined_agent_re_register_is_noop`
- `TestApprovalTokenReplay::test_operator_queue_drained_by_kill_all`
- `TestApprovalTokenReplay::test_revoked_agent_not_active_regardless_of_approval`
- `TestAgentSelfRevival::test_revoked_id_stays_revoked_after_re_register_attempt`
- `TestAgentSelfRevival::test_new_id_after_revocation_starts_fresh`

### Fuzz Tests — `test_enterprise/test_fuzz.py` (15 tests)

- `TestAllowEntryFuzz::test_arbitrary_text_never_crashes`
- `TestAllowEntryFuzz::test_regex_shaped_inputs`
- `TestAllowEntryFuzz::test_no_injection_chars_in_host`
- `TestAllowEntryFuzz::test_invalid_port_range_rejected`
- `TestAllowEntryFuzz::test_valid_port_range_accepted`
- `TestPolicyBundleFuzz::test_arbitrary_agent_dicts`
- `TestPolicyBundleFuzz::test_arbitrary_agent_id_keys`
- `TestPolicyBundleFuzz::test_float_valid_from`
- `TestPolicyBundleFuzz::test_float_valid_until`
- `TestPolicyBundleFuzz::test_bundle_with_1000_agents`
- `TestPolicyBundleFuzz::test_very_long_policy_id`
- `TestSanitizeFuzz::test_sanitize_arbitrary_text`
- `TestSanitizeFuzz::test_printable_chars_always_succeed`
- `TestSanitizeFuzz::test_wfp_profile_arbitrary_process_name`
- `TestSanitizeFuzz::test_wfp_profile_arbitrary_profile_name`

### Birth Tag v2 — `test_enterprise/test_birth_tag_v2.py` (14 tests)

- `test_build_payload_is_deterministic`
- `test_build_payload_contains_all_fields`
- `test_build_payload_different_ts`
- `test_stamp_returns_hex_sig`
- `test_stamp_writes_scid_sig_and_sts`
- `test_sign_then_verify_ok`
- `test_verify_fails_on_missing_sig`
- `test_verify_fails_on_corrupted_sig`
- `test_verify_fails_with_wrong_key`
- `test_verify_fails_on_expired_ts`
- `test_verify_passes_before_expiry`
- `test_verify_fails_if_scid_tampered`
- `test_verify_fails_on_missing_sts`
- `test_sign_verify_real_dpapi`

### Message Validator — `test_enterprise/test_msg_validator.py` (14 tests)

- `TestDisabled::test_disabled_always_accepts`
- `TestDisabled::test_module_level_validate_disabled`
- `TestFastPath::test_accepted_within_ttl`
- `TestFastPath::test_cache_size_increases_on_new_pid`
- `TestSlowPath::test_valid_birth_time_accepted`
- `TestSlowPath::test_ttl_expiry_triggers_recheck`
- `TestMismatch::test_pid_recycled_detected`
- `TestMismatch::test_mismatch_flushes_all_pid_entries`
- `TestMismatch::test_process_not_found_rejected`
- `TestMismatch::test_different_pids_not_affected_by_flush`
- `TestProcessExitHook::test_exit_flushes_pid_entries`
- `TestProcessExitHook::test_exit_for_unknown_pid_is_no_op`
- `TestProcessExitHook::test_exit_does_not_affect_other_pids`
- `TestInvalidateAll::test_flushes_entire_cache`

### Version Gate — `test_enterprise/test_version_gate.py` (14 tests)

- `TestPhaseNone::test_no_flag_accepts_unsigned_peer`
- `TestPhaseNone::test_no_flag_phase_is_none`
- `TestGracePeriod::test_unsigned_peer_accepted_in_grace`
- `TestGracePeriod::test_signed_valid_peer_accepted_in_grace`
- `TestGracePeriod::test_signed_invalid_peer_rejected_in_grace`
- `TestGracePeriod::test_phase_is_grace_before_sunset`
- `TestAfterSunset::test_unsigned_peer_rejected_after_sunset`
- `TestAfterSunset::test_signed_valid_peer_accepted_after_sunset`
- `TestAfterSunset::test_expired_sig_rejected_after_sunset`
- `TestAfterSunset::test_phase_is_sunset_after_date`
- `TestAfterSunset::test_no_pubkey_with_sig_present_rejected`
- `TestEmergencyOverride::test_override_accepts_all_peers`
- `TestEmergencyOverride::test_override_phase_returns_override`
- `TestBadSunsetFormat::test_invalid_date_disables_enforcement`

### Policy Signing — `test_enterprise/test_policy_sign.py` (12 tests)

- `TestSignPolicy::test_sign_adds_sig_field`
- `TestSignPolicy::test_sign_adds_signed_by_pub`
- `TestSignPolicy::test_signing_does_not_modify_other_fields`
- `TestSignPolicy::test_sign_twice_produces_different_sigs`
- `TestVerifyPolicySignature::test_valid_signature_verifies`
- `TestVerifyPolicySignature::test_tampered_policy_fails_verify`
- `TestVerifyPolicySignature::test_wrong_public_key_fails_verify`
- `TestVerifyPolicySignature::test_empty_sig_fails_verify`
- `TestVerifyPolicySignature::test_invalid_hex_sig_fails_verify`
- `TestSignedPolicyEnforcement::test_signed_policy_allows_action`
- `TestSignedPolicyEnforcement::test_tampered_policy_is_denied_by_enforcer`
- `TestSignedPolicyEnforcement::test_signed_policy_saved_and_loaded`

### Registry Capacity — `test_enterprise/test_registry_cap.py` (12 tests)

- `TestDiscoveryCap::test_cap_stops_at_max`
- `TestDiscoveryCap::test_cap_emits_log_warning`
- `TestDiscoveryCap::test_below_cap_returns_all`
- `TestDiscoveryCap::test_high_hwnd_values_not_sign_extended`
- `TestDiscoveryCap::test_exactly_at_cap_no_warning`
- `TestPidStampVolumeGuard::test_excess_stamps_from_same_pid_excluded`
- `TestPidStampVolumeGuard::test_pid_volume_emits_log_warning`
- `TestPidStampVolumeGuard::test_different_pids_each_allowed_up_to_limit`
- `TestPidStampVolumeGuard::test_exactly_at_pid_limit_no_warning`
- `TestStampBirthTagSignedWiring::test_scid_sig_stamped_when_identity_provided`
- `TestStampBirthTagSignedWiring::test_scid_sig_not_stamped_without_identity`
- `TestStampBirthTagSignedWiring::test_signing_failure_does_not_prevent_unsigned_tag`

### Supply Chain Integrity — `test_enterprise/test_supply_chain.py` (11 tests)

- `TestLiteLLMSupplyChain::test_litellm_not_backdoored_version`
- `TestLiteLLMSupplyChain::test_litellm_version_documented_if_present`
- `TestCryptographyVersion::test_cryptography_at_minimum_safe_version`
- `TestCryptographyVersion::test_cryptography_not_using_sect_curves`
- `TestCryptographyVersion::test_x509_verification_path_not_used`
- `TestWfpScriptIntegrity::test_generate_powershell_is_deterministic`
- `TestWfpScriptIntegrity::test_sha256_of_script_is_stable`
- `TestWfpScriptIntegrity::test_different_profiles_produce_different_hashes`
- `TestWfpScriptIntegrity::test_tampered_script_has_different_hash`
- `TestDependencyAudit::test_direct_deps_no_known_cves`
- `TestDependencyAudit::test_all_installed_packages_audit_informational`

### Resource Exhaustion — `test_enterprise/test_resource_exhaustion.py` (10 tests)

- `TestLedgerExhaustion::test_write_10000_entries`
- `TestLedgerExhaustion::test_verify_10000_entries`
- `TestOperatorQueueExhaustion::test_submit_1000_items`
- `TestOperatorQueueExhaustion::test_get_pending_returns_all_1000`
- `TestOperatorQueueExhaustion::test_deny_all_1000_under_budget`
- `TestPolicyExhaustion::test_construct_500_agents`
- `TestPolicyExhaustion::test_check_500_agents_under_budget`
- `TestWfpExhaustion::test_200_allow_entries`
- `TestDeepNesting::test_10000_allowed_actions`
- `TestDeepNesting::test_10000_actions_check_timing`

### Cache Bus — `test_enterprise/test_cache_bus.py` (8 tests)

- `test_register_and_count`
- `test_no_duplicate_registration`
- `test_unregister`
- `test_unregister_not_registered_is_safe`
- `test_notify_calls_all_callbacks`
- `test_notify_continues_after_crashing_callback`
- `test_notify_with_no_callbacks_is_safe`
- `test_multiple_distinct_pids`

### Stress / Concurrency — `test_enterprise/test_stress_concurrent.py` (8 tests)

- `TestControlPlaneConcurrency::test_50_threads_mixed_operations`
- `TestControlPlaneConcurrency::test_100_threads_register_simultaneously`
- `TestControlPlaneConcurrency::test_kill_all_during_registration`
- `TestOperatorQueueConcurrency::test_100_threads_submit_unique_ids`
- `TestOperatorQueueConcurrency::test_50_threads_approve_same_item`
- `TestOperatorQueueConcurrency::test_50_submit_50_approve_simultaneously`
- `TestAgentLedgerConcurrency::test_sequential_writes_safe`
- `TestAgentLedgerConcurrency::test_concurrent_writes_documented_unsafe`

### E2E Chain — `test_enterprise/test_e2e_chain.py` (4 tests)

- `TestEndToEndChain::test_full_chain`
- `TestEndToEndChain::test_chain_with_tampered_policy_fails`
- `TestEndToEndChain::test_chain_classification_ceiling`
- `TestEndToEndChain::test_chain_revoked_agent_denied`

### Discovery Config — `test_enterprise/test_discovery_config.py` (3 tests)

- `test_defaults`
- `test_env_override`
- `test_default_cap_is_32`

---

## selfconnect-enterprise — SDK Tests (159 tests)

**90 tests run on all platforms:**

- `tests/test_action_queue.py::TestEnqueue::test_enqueue_returns_item`
- `tests/test_action_queue.py::TestEnqueue::test_enqueue_adds_to_queue`
- `tests/test_action_queue.py::TestEnqueue::test_multiple_enqueues`
- `tests/test_action_queue.py::TestEnqueue::test_enqueue_publishes_queue_event`
- `tests/test_action_queue.py::TestGetQueue::test_empty_queue`
- `tests/test_action_queue.py::TestGetQueue::test_queue_includes_pending`
- `tests/test_action_queue.py::TestCancel::test_cancel_removes_item`
- `tests/test_action_queue.py::TestCancel::test_cancel_nonexistent`
- `tests/test_action_queue.py::TestCancel::test_cancel_only_removes_target`
- `tests/test_action_queue.py::TestPause::test_pause_sets_flag`
- `tests/test_action_queue.py::TestRunAlreadyRunning::test_run_while_running_is_noop`
- `tests/test_action_queue.py::TestWaitExecution::test_wait_action_executes`
- `tests/test_action_queue.py::TestCommandParsing::test_click_command_resolves_detection`
- `tests/test_action_queue.py::TestCommandParsing::test_click_command_raises_when_not_found`
- `tests/test_action_queue.py::TestCommandParsing::test_click_command_no_attached_window`
- `tests/test_action_queue.py::TestCommandParsing::test_type_command`
- `tests/test_action_queue.py::TestCommandParsing::test_unknown_command_defaults_to_type`
- `tests/test_action_queue.py::TestGetAll::test_get_all_includes_history`
- `tests/test_action_queue.py::TestGetAll::test_history_capped_at_50`
- `tests/test_claudego_dashboard.py::TestRoot::test_status_200`
- `tests/test_claudego_dashboard.py::TestRoot::test_is_html`
- `tests/test_claudego_dashboard.py::TestRoot::test_contains_claudego`
- `tests/test_claudego_dashboard.py::TestHealth::test_ok_true`
- `tests/test_claudego_dashboard.py::TestHealth::test_scanner_true`
- `tests/test_claudego_dashboard.py::TestTerminals::test_shape`
- `tests/test_claudego_dashboard.py::TestLog::test_shape`
- `tests/test_claudego_dashboard.py::TestRules::test_get_shape`
- `tests/test_claudego_dashboard.py::TestRules::test_post_ok`
- `tests/test_claudego_dashboard.py::TestRules::test_post_persists`
- `tests/test_claudego_dashboard.py::TestApprove::test_unknown_returns_false`
- `tests/test_claudego_dashboard.py::TestApprove::test_known_approves`
- `tests/test_claudego_dashboard.py::TestDeny::test_unknown_returns_false`
- `tests/test_claudego_dashboard.py::TestDeny::test_known_denies`
- `tests/test_claudego_scanner.py::TestPartnerConfig::test_defaults`
- `tests/test_claudego_scanner.py::TestPartnerConfig::test_invalid_default_action_raises`
- `tests/test_claudego_scanner.py::TestScanEvent::test_to_dict_shape`
- `tests/test_claudego_scanner.py::TestScanEvent::test_timestamp_auto_set`
- `tests/test_claudego_scanner.py::TestScanEvent::test_agent_type_in_dict`
- `tests/test_claudego_scanner.py::TestDetectAgentType::test_claude_code`
- `tests/test_claudego_scanner.py::TestDetectAgentType::test_local_model_by_local_agent`
- `tests/test_claudego_scanner.py::TestDetectAgentType::test_local_model_by_agent_b`
- `tests/test_claudego_scanner.py::TestDetectAgentType::test_observer`
- `tests/test_claudego_scanner.py::TestDetectAgentType::test_unknown`
- `tests/test_claudego_scanner.py::TestScanner::test_empty_state`
- `tests/test_claudego_scanner.py::TestScanner::test_get_rules_shape`
- `tests/test_claudego_scanner.py::TestScanner::test_set_rules`
- `tests/test_claudego_scanner.py::TestScanner::test_audit_log_limit`
- `tests/test_claudego_scanner.py::TestScanner::test_callback_fires`
- `tests/test_claudego_scanner.py::TestScanner::test_manual_approve_unknown_hwnd`
- `tests/test_claudego_scanner.py::TestScanner::test_manual_deny_unknown_hwnd`
- `tests/test_claudego_scanner.py::TestScanner::test_manual_approve_sends_y`
- `tests/test_claudego_scanner.py::TestScanner::test_manual_deny_sends_n`
- `tests/test_claudego_scanner.py::TestScanner::test_dry_run_skips_inject`
- `tests/test_claudego_scanner.py::TestScanner::test_manual_approve_emits_event`
- `tests/test_claudego_scanner.py::TestScanner::test_manual_deny_emits_event`
- `tests/test_event_bus.py::TestSubscribePublish::test_subscribe_and_receive`
- `tests/test_event_bus.py::TestSubscribePublish::test_multiple_subscribers`
- `tests/test_event_bus.py::TestSubscribePublish::test_unsubscribe`
- `tests/test_event_bus.py::TestSubscribePublish::test_unsubscribe_nonexistent_is_safe`
- `tests/test_event_bus.py::TestSubscribePublish::test_channel_isolation`
- `tests/test_event_bus.py::TestSubscribeAll::test_subscribe_all_channels`
- `tests/test_event_bus.py::TestSubscribeAll::test_unsubscribe_all`
- `tests/test_event_bus.py::TestDeadSubscriberCleanup::test_dead_subscriber_removed`
- `tests/test_event_bus.py::TestLogEntry::test_log_entry_format`
- `tests/test_event_bus.py::TestLogEntry::test_log_entry_fail`
- `tests/test_main_logging.py::test_cors_preflight_not_blocked_by_auth`
- `tests/test_main_logging.py::test_rotating_error_log_handler_configured`
- `tests/test_schemas.py::TestWindowInfo::test_valid`
- `tests/test_schemas.py::TestWindowInfo::test_active_true`
- `tests/test_schemas.py::TestWindowInfo::test_missing_hwnd`
- `tests/test_schemas.py::TestDetection::test_valid`
- `tests/test_schemas.py::TestDetection::test_conf_float`
- `tests/test_schemas.py::TestDetection::test_missing_field`
- `tests/test_schemas.py::TestVLDescription::test_valid`
- `tests/test_schemas.py::TestVLDescription::test_empty_tags`
- `tests/test_schemas.py::TestQueueItem::test_pending_state`
- `tests/test_schemas.py::TestQueueItem::test_done_state`
- `tests/test_schemas.py::TestQueueItem::test_all_kinds`
- `tests/test_schemas.py::TestLogEntry::test_valid`
- `tests/test_schemas.py::TestLogEntry::test_fail_status`
- `tests/test_schemas.py::TestMacroStep::test_valid`
- `tests/test_schemas.py::TestMacroStep::test_type_action`
- `tests/test_schemas.py::TestHealthStatus::test_all_ok`
- `tests/test_schemas.py::TestHealthStatus::test_all_down`
- `tests/test_schemas.py::TestActionRequest::test_minimal_click`
- `tests/test_schemas.py::TestActionRequest::test_with_coords`
- `tests/test_schemas.py::TestActionRequest::test_type_action`
- `tests/test_schemas.py::TestWSMessage::test_detections_channel`
- `tests/test_schemas.py::TestWSMessage::test_health_channel`
- `tests/test_schemas.py::TestWSMessage::test_valid_channels`

**69 tests Windows-only (skip on Linux — require ctypes.windll):**


#### test_antigravity_controller.py (32 tests)

- `test_standalone_match`
- `test_case_insensitive`
- `test_exclude_google_chrome`
- `test_exclude_vscode`
- `test_unrelated_window`
- `test_empty_string`
- `test_cursor_editor`
- `test_antigravity_settings`
- `test_construction_defaults`
- `test_connected_at_auto_set`
- `test_is_valid_false_for_fake_hwnd`
- `test_str_representation`
- `test_explicit_fields`
- `test_on_returns_self`
- `test_chaining`
- `test_unknown_event_raises`
- `test_is_running_before_start`
- `test_stop_without_start`
- `test_multiple_handlers_same_event`
- `test_emit_response`
- `test_emit_model_changed`
- `test_handler_exception_does_not_propagate`
- `test_default_poll_interval`
- `test_custom_poll_interval`
- `test_connect_returns_session`
- `test_connect_title_is_antigravity`
- `test_connect_model_non_empty`
- `test_is_valid`
- `test_list_buttons_non_empty`
- `test_send_button_present`
- `test_get_model`
- `test_chat_roundtrip`

#### test_approval_partner.py (37 tests)

- `test_detects_do_you_want_to_proceed`
- `test_detects_allow_for_project`
- `test_detects_yes_no_always`
- `test_detects_arrow_prompt`
- `test_no_false_positive_on_regular_output`
- `test_extracts_bash_tool`
- `test_extracts_allow_pattern`
- `test_extracts_read_tool`
- `test_returns_none_on_no_tool`
- `test_handles_nested_parens_gracefully`
- `test_deny_rm`
- `test_deny_rmdir`
- `test_deny_curl`
- `test_deny_takes_precedence_over_allow`
- `test_allow_git`
- `test_allow_npm`
- `test_allow_python`
- `test_allow_read`
- `test_allow_write`
- `test_unknown_returns_none`
- `test_custom_allow_pattern`
- `test_custom_deny_pattern`
- `test_known_allow`
- `test_known_deny`
- `test_unknown_with_escalate_default`
- `test_unknown_with_approve_default`
- `test_unknown_with_deny_default`
- `test_none_tool_with_approve_all`
- `test_none_tool_with_deny_all`
- `test_none_tool_escalate`
- `test_defaults`
- `test_invalid_default_action_raises`
- `test_approve_all_config`
- `test_custom_patterns_override_defaults`
- `test_all_default_allow_patterns_are_valid_globs`
- `test_all_default_deny_patterns_are_valid_globs`
- `test_no_overlap_in_defaults`

---

## selfconnect — Win32 SDK Test (51 tests)

**45 pass / 6 skip display-dependent (require visible top-level windows)**

- `test_version` — SDK version string is present and non-empty
- `test_window_discovery` — EnumWindows returns at least one handle
- `test_find_target` — find_window locates a known process by name
- `test_window_text` — GetWindowText returns a string
- `test_window_rect` — GetWindowRect returns a 4-tuple of ints
- `test_clipboard` — SetClipboardData / GetClipboardData round-trip
- `test_capture` — BitBlt screen capture returns bytes
- `test_window_pool` — WindowPool context manager opens and closes cleanly
- `test_send_keys_import` — SendInput module imports without error
- `test_wait_for_window` — wait_for_window returns within timeout
- `test_layer4_continuity` — Layer 4 continuity check passes

*(6 additional display-dependent tests skip in headless CI)*

---

## selfconnect — SDK Tests (159 tests)

*(Same test files as selfconnect-enterprise/sdk/tests/ — shared SDK codebase)*

90 run on all platforms, 69 Windows-only — see selfconnect-enterprise SDK section above for full list.

---

## tsk-protocol — Unit Tests (36 tests)

- `HMAC produces deterministic output`
- `HMAC differs with different inputs`
- `HMAC differs with different secrets`
- `Constant-time compare: equal strings pass`
- `Constant-time compare: unequal strings fail`
- `Constant-time compare: different lengths fail`
- `Static segment is deterministic`
- `TOTP segment changes across windows`
- `TOTP segment stable within window`
- `HOTP segment changes with counter`
- `Segment value fills correct length`
- `Generated key has correct length`
- `Generated key is deterministic for same time`
- `Key differs at different times (TOTP segments change)`
- `Key contains valid checksum`
- `Valid key passes validation`
- `All segment results are valid`
- `TOTP tolerance: key from ±1 window still valid`
- `HOTP counter: key with counter=0 valid, advances counter`
- `HOTP lookahead: counter+3 valid within lookahead=5`
- `Wrong key length rejected`
- `Tampered key rejected (single char flip)`
- `Expired TOTP rejected (5 min old)`
- `Replay with wrong HOTP counter rejected`
- `Wrong shared secret rejected`
- `Positionally shifted key rejected`
- `All-zeros key rejected`
- `Random key rejected`
- `Hybrid key (old rotating + current static) rejected`
- `Segment failure pattern detects stolen key`
- `Different clients get different maps`
- `Revoked client (missing map) fails validation`
- `Key at exact TOTP window boundary`
- `Very long segment value (padOrTruncate)`
- `Multiple HOTP advances within lookahead`
- `HOTP counter=6 beyond lookahead=5 fails`

### tsk-protocol — Adversarial Attack Suite (12 attack scenarios, ~389,076 total attempts)

- **ATTACK 1: Pure Brute Force** — 100,000 random 52-char strings — none match
- **ATTACK 2: Captured Key Replay** — 600 replay attempts across 10 minutes of time offsets — all rejected
- **ATTACK 3: Statistical Analysis** — 1,000 intercepted keys + 10,000 forge attempts using identified static positions — all rejected
- **ATTACK 4: Known Plaintext / Secret Guessing** — 50,000 secret-guessing attempts with algorithm knowledge — all rejected
- **ATTACK 5: Checksum Forgery** — 10,000 attempts to forge valid checksum without the HMAC secret — all rejected
- **ATTACK 6: Timing Attack** — 4,000 validation time measurements to detect segment validity leakage — variance within noise
- **ATTACK 7: Birthday Attack** — 50,000 key collision checks — collision space is 2^312, birthday bound ~2^156
- **ATTACK 8: Partial Key Recovery** — 50,000 attempts with known static segments, guessing rotating segments — all rejected
- **ATTACK 9: Bit Flipping** — 3,276 systematic single-bit mutations across entire key — all rejected
- **ATTACK 10: Flood / DoS** — 100,000 rapid-fire validation attempts — server holds
- **ATTACK 11: TOTP Window Edge Race** — 200 boundary race conditions at exact TOTP window transitions — all handled correctly
- **ATTACK 12: Entropy Analysis** — Chi-squared test on 520,000 characters — output indistinguishable from random

### tsk-protocol — Adversarial Proof (6 scenarios)

- `Attack 1: Stolen Key Replay — TOTP window expired`
- `Attack 2: Tampered Key — single character mutation`
- `Attack 3: Brute Force Position Guessing — scrambled segments`
- `Attack 4: Oversized Header DoS — 100KB key header`
- `Attack 5: Stolen Key Structural Analysis — rotating segments spliced into static positions`
- `Attack 6: Missing TSK Headers — request without TSK layer rejected`
- `Full Flow: Provision → Generate → Validate → HOTP counter advance → replay rejected`

### tsk-protocol — Ultra Bridge Test (11 scenarios)

- `[1] Happy Path — BPC pass + TSK pass + identity match`
- `[2] BPC Layer Failure — TSK never called`
- `[3] TSK Layer Failure — BPC passes, TSK key is expired`
- `[4] TSK Headers Missing — request has BPC headers but no TSK layer`
- `[5] Identity Binding Mismatch — BPC pairId maps to different clientId`
- `[6] Identity Binding — pairId unknown (resolves to null)`
- `[7] Identity Binding Unavailable — BPC result missing pairId`
- `[8] Tampered TSK Key — 1-char mutation at position 10`
- `[9] Wrong TSK Client ID — valid key but wrong clientId header`
- `[10] ULTRA_SECURITY_LAYERS Contract`
- `[11] BPC Scope Propagation (HIGH-03)`

---

## bpc-protocol — All Tests (100 tests across 4 files)


### Cryptographic Core — `packages/core/tests/crypto.test.ts` (8 tests)

- `ECDSA P-256 key pair generation produces valid keys`
- `sign() produces a non-empty base64url signature`
- `verify() returns true for a valid signature`
- `verify() returns false for a tampered payload`
- `verify() returns false for a wrong key`
- `canonicalize() produces stable JSON regardless of key order`
- `nonce generation produces unique values`
- `nonce generation produces correct length`

### Client SDK — `packages/client-sdk/tests/client.test.ts` (22 tests)

- `createBPCClient returns a client with sign method`
- `signed request has all required headers`
- `X-BPC-Timestamp is within 5 seconds of now`
- `X-BPC-Nonce is unique per request`
- `X-BPC-Signed-Data contains method, path, nonce, timestamp, scope, bodyHash`
- `X-BPC-Signature is a non-empty string`
- `body hash is SHA-256 of body`
- `empty body produces correct hash`
- `scope is included in signed data`
- `pairId is included in signed data`
- `different paths produce different signatures`
- `different methods produce different signatures`
- `different bodies produce different signatures`
- `client handles missing body gracefully`
- `client uses provided timestamp`
- `client uses provided nonce`
- `signedData is base64url encoded`
- `signature verifies against public key`
- `tampered signedData fails verification`
- `tampered signature fails verification`
- `client works with DELETE method (no body)`
- `client works with GET method`

### Server Middleware — `packages/server/tests/server.test.ts` (26 tests)

- `should verify a correctly signed request`
- `should reject a replayed request (same nonce)`
- `should reject a tampered payload (modified path after signing)`
- `should reject an expired timestamp`
- `should reject an unknown pair ID`
- `should reject a request with a forged signature`
- `should reject a request with missing headers`
- `should reject a revoked pair`
- `should reject a body hash mismatch`
- `should reject DELETE on a read-only scoped pair`
- `should lock a pair after 10 consecutive signature failures`
- `should reject requests when rate limited`
- `should reject an expired pair (expiresAt in the past)`
- `should reject a version mismatch`
- `should reject an oversized X-BPC-Signed-Data header (DoS guard)`
- `should reject an oversized X-BPC-Signature header (DoS guard)`
- `should lock via failedSigs check even if status field lags (parallel-race guard)`
- `should support approval workflow`
- `should throw on invalid approval token`
- `should unlock a locked pair`
- `should return 0 threat score with no requests`
- `should increase threat score with failures`
- `should track counters accurately`
- `should track per-pair counters`
- `should allow requests within limit`
- `should detect replay nonces`

### Security Hardening — `packages/server/tests/security.test.ts` (45 tests)

- `rejects registration with empty secretHash`
- `rejects registration with short secretHash (< 43 chars)`
- `rejects registration with null secretHash`
- `middleware rejects request when pair has empty secretHash (defense-in-depth)`
- `middleware rejects request with wrong HMAC (no fallback)`
- `accepts a valid request with correct HMAC`
- `handleRotation returns error result for unknown pair (no crash)`
- `handleRotation succeeds with valid rotation payload`
- `handleRotation rejects expired timestamp (no crash)`
- `hashSecret produces HKDF output (43 chars, base64url)`
- `hashSecret is deterministic`
- `hashSecret produces different outputs for different secrets`
- `hashSecret output is not a raw SHA-256 hex string`
- `listRedacted() strips secretHash and pubJwk`
- `listRedacted() returns only safe fields`
- `verifyAdminRequest() denies request with no config (fail-closed)`
- `verifyAdminRequest() denies request with wrong bearer token`
- `verifyAdminRequest() denies request with missing Authorization header`
- `verifyAdminRequest() allows request with correct bearer token`
- `verifyAdminRequest() uses custom verifier when provided`
- `verifyAdminRequest() denies when custom verifier returns false`
- `verifyAdminRequest() requires BOTH bearerToken AND verifier to pass when both set`
- `canonicalize throws on __proto__ key`
- `canonicalize throws on constructor key`
- `canonicalize throws on prototype key`
- `canonicalize throws on nested object values`
- `canonicalize throws on array values`
- `canonicalize accepts valid flat payload`
- `canonicalize is deterministic (key order independent)`
- `middleware rejects request with __proto__ in signedData`
- `capacity guard evicts keys when limit exceeded`
- `per-IP limit does not affect per-pairId limit`
- `ipRateLimiter in BPCServerConfig fires before pairId is read`
- `ipRateLimiter does not affect requests from different IPs`
- `rejects unknown HTTP method (TRACE)`
- `rejects pairId with special characters (injection attempt)`
- `rejects payload with non-UUID nonce`
- `rejects registration with invalid scope`
- `rejects registration with invalid mode`
- `rejects secrets shorter than 16 characters`
- `rejects secrets with only one special character`
- `accepts a valid hardened secret` *(normalized registry label; this test
  checks the package's secret-format rule and does not establish a DoD Impact
  Level authorization or compliance status)*
- `MIN_SECRET_LENGTH is 16`
- `completes a full request lifecycle with all hardening active`
- `dual-track rate limiters work together without interfering`

---

## words-of-wisdom — Server Tests (12 tests)

*(Separate application — auth and quotes API)*

### auth.logout.test.ts (1 test)

- `logout clears session and redirects`

### quotes.test.ts (11 tests)

*(Quote CRUD, voting, and retrieval API tests)*
