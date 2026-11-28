# Documentation index

Every document in this directory, sorted by what kind of document it is.
The kind matters because the directory mixes descriptions of the product as
it is with plans and dated reports, and they do not age the same way.

**How to read them.** A dated record describes the code on its date. A plan
describes an intention. When either disagrees with a document in the first
two groups, or with the code, the record or the plan is the one that is out
of date.

`tests/test_docs_index.py` fails when a document is added here without being
listed, so nothing new can land unclassified.

## Operating and reference

How to run, configure, release and test One Link.

- [ENVIRONMENT.md](ENVIRONMENT.md): every `ONE_LINK_*` variable
- [NETWORK_CONTACTS.md](NETWORK_CONTACTS.md): what a default install contacts
- [RENDEZVOUS_DEPLOY.md](RENDEZVOUS_DEPLOY.md): operating a rendezvous server
- [ROLLING_A_SOURCE_INSTALL.md](ROLLING_A_SOURCE_INSTALL.md): updating a source install
- [PHASE_E_OPERATOR_RUNBOOK.md](PHASE_E_OPERATOR_RUNBOOK.md): operator runbook
- [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md): release sign-off
- [RELEASE_PROTECTION.md](RELEASE_PROTECTION.md): release and CI-gate protection
- [REPOSITORY_POLICY.md](REPOSITORY_POLICY.md): required repository checks
- [DEPENDENCY_QUALIFICATION.md](DEPENDENCY_QUALIFICATION.md): how a dependency is accepted
- [TESTING.md](TESTING.md): testing strategy
- [ONE_LINK_VALIDATION_GATES.md](ONE_LINK_VALIDATION_GATES.md): validation gates
- [TRANSFER_DOCTOR_AND_TORTURE.md](TRANSFER_DOCTOR_AND_TORTURE.md): transfer diagnosis and the torture gate
- [PERFORMANCE_LAB.md](PERFORMANCE_LAB.md): the performance lab
- [WIRE_COMPATIBILITY.md](WIRE_COMPATIBILITY.md): mixed-version wire baseline
- [FILE_ENGINE_V2_MIGRATION.md](FILE_ENGINE_V2_MIGRATION.md): file engine v2 migration guide

## Design and specification

What the product is meant to do and why it is built the way it is.

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [SECURITY.md](SECURITY.md): threat model and hardening contract
- [SOVEREIGNTY.md](SOVEREIGNTY.md)
- [SOVEREIGN_NETWORK_BLUEPRINT.md](SOVEREIGN_NETWORK_BLUEPRINT.md)
- [GOVERNANCE.md](GOVERNANCE.md)
- [PRINCIPLES.md](PRINCIPLES.md)
- [DOCTRINE_OF_INVISIBILITY.md](DOCTRINE_OF_INVISIBILITY.md)
- [PROVEN_SURFACE.md](PROVEN_SURFACE.md)
- [CAPSULE_DURABILITY.md](CAPSULE_DURABILITY.md)
- [TRANSACTIONAL_UPDATER.md](TRANSACTIONAL_UPDATER.md)
- [LIVING_PRESENCE_ARCHITECTURE.md](LIVING_PRESENCE_ARCHITECTURE.md): voice and video
- [PHONE_TIER.md](PHONE_TIER.md)
- [ONE_SETUP_FIRST_RUN_EXPERIENCE.md](ONE_SETUP_FIRST_RUN_EXPERIENCE.md)
- [COHERENCE_TRANSFER_BRAIN.md](COHERENCE_TRANSFER_BRAIN.md)
- [PRIOR_KNOWLEDGE_TRANSFER.md](PRIOR_KNOWLEDGE_TRANSFER.md)
- [UNIVERSAL_COMMS_FABRIC.md](UNIVERSAL_COMMS_FABRIC.md)
- [`decisions/`](decisions/): architecture decision records, one per decision
- [`architecture/`](architecture/): service-level notes
- [`formal/`](formal/): formal models

## Plans and roadmaps

Statements of intent, each written at one moment.

- [ROADMAP.md](ROADMAP.md)
- [WE_ARE_ONE_MASTER_PLAN.md](WE_ARE_ONE_MASTER_PLAN.md)
- [COHERENCE_MESH_PLAN.md](COHERENCE_MESH_PLAN.md)
- [FILE_ENGINE_V2_PLAN.md](FILE_ENGINE_V2_PLAN.md)
- [PHASE_A2_QUIC_CUTOVER_PLAN.md](PHASE_A2_QUIC_CUTOVER_PLAN.md)
- [PHASE_C_N_ROADMAP.md](PHASE_C_N_ROADMAP.md)
- [ENGINEERING_95_PROGRAM.md](ENGINEERING_95_PROGRAM.md)
- [LAUNCH_BLOCKERS.md](LAUNCH_BLOCKERS.md)
- [LAUNCH_CHECKLIST.md](LAUNCH_CHECKLIST.md)
- [WEBSITE_CAPABILITY_CLOSURE.md](WEBSITE_CAPABILITY_CLOSURE.md)

## Dated records

Audits, benchmark baselines and checklists as they stood on their date.

- [SECURITY_AUDIT_v0.7.0.md](SECURITY_AUDIT_v0.7.0.md)
- [TRANSFER_RELIABILITY_AUDIT_2026-07-21.md](TRANSFER_RELIABILITY_AUDIT_2026-07-21.md)
- [UX_AUDIT_2026-05-17.md](UX_AUDIT_2026-05-17.md)
- [UX_RED_TEAM_AUDIT_2026_05_16.md](UX_RED_TEAM_AUDIT_2026_05_16.md)
- [TEST_SUITE_SKIP_AUDIT.md](TEST_SUITE_SKIP_AUDIT.md)
- [BENCH_BASELINE_PHASE_B.md](BENCH_BASELINE_PHASE_B.md)
- [BENCH_BASELINE_PHASE_C.md](BENCH_BASELINE_PHASE_C.md)
- [FILE_ENGINE_BENCHMARKS.md](FILE_ENGINE_BENCHMARKS.md)
- [CALL_UI_MANUAL_CHECKLIST.md](CALL_UI_MANUAL_CHECKLIST.md)
- [PRIVACY_PANEL_MANUAL_CHECKLIST.md](PRIVACY_PANEL_MANUAL_CHECKLIST.md)
- [`audit/`](audit/): audit reports and the evidence behind them
