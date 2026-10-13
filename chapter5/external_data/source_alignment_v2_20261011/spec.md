# Source alignment v2 — bounded data correction

The user requested eliminating the identified differences. Create an independent, reviewable source alignment version; preserve all frozen input packages, results, roles and gate decisions.

1. Freeze actual CTID source bytes: original mapping CSV at191e870 and the dated KEV release at a85e55a. Check their Git blobs and zip member hashes before parsing.
2. Reconstruct only the original880 development CVEs and858 registered external IDs. Never compare or score reserved labels. Use the fixed31 Enterprise parent IDs, collapse child IDs, retain each raw technique and stage as provenance.
3. Original labels must exactly match reconstructed CTID labels; reject any unexpected discrepancy. Same-CVE author observations receive this canonical view; preserve each author's original variant and row/file origin. Do not union ambiguous variants.
4. CTID-supported labels omitted from an author observation are included in its canonical view. Author-only labels unsupported by the chosen CTID source remain UNKNOWN and are excluded from canonical positives. UNKNOWN is not a confirmed negative; export a separate exclusion list for future loss/scoring integration.
5. For an external-only CVE with exclusively out-of-domain CTID mappings, quarantine instead of inventing an Enterprise crosswalk. All other external-only labels stay as registered author labels, clearly marked externally curated and not CTID revalidated.
6. Emit records, aligned overlap views,73-resolution ledger, UNKNOWN ledger, domain quarantine, role/fold coverage and a reproducible input/output manifest. This is data preparation; future training must explicitly honor UNKNOWN exclusions and be newly registered.
7. Do not normalize away statistical prevalence differences. Keep CWE/CPE metadata and the92 NVD source disputes unchanged. Do not launch training or recalculate model scores.
8. Acceptance:619 canonical overlap views have zero disagreement; original880 canonical sets unchanged;73 differences traced to raw CTID; two author duplicate IDs resolve via authority without union; domain-conflicting external records excluded; no protected IDs in sample/label/evidence outputs (the fold protection registry retains identifiers only). Test observable behaviors, repeat generation, verify bytes/roles/ledgers and original runtime bindings.

No source policy can prove that CTID exhausts all possible techniques. No human IAA or full semantic adjudication is claimed. The original study already excluded the619 repeated IDs from additional Train; aligning them is not a measured improvement to the completed experiment.

