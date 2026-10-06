# Scope comparison supporting v36.0

Checked 2026-09-06 against primary sources. This is a comparison of specified
workflows, not an implementation benchmark or a claim of universal priority.

| Source and inspected sections | Specified control point | Relationship to DIB |
| --- | --- | --- |
| [RFC 8520](https://www.rfc-editor.org/rfc/rfc8520.html), §§1.1 and 1.8 | Local administrators decide how recommendations are instantiated; profile changes follow deployment-specific approval flows. | Local discretion is already part of MUD. DIB specifies the additional interaction between shared disputes, approval invalidation, local veto provenance, and recovery. |
| [POLARIS v1](https://arxiv.org/html/2511.22017v1), §§III-A, III-C, III-D | Resource owners make final access decisions after verifiable-attribute policy evaluation. Session keys bind authentication and resource access. | DIB assumes authenticated identities and addresses the lifecycle of per-site MUD authorizations following challenged traffic evidence. The inspected access/session workflows do not specify DIB's shared-dispute/local-veto restoration sequence. |
| [FIDEM v1](https://arxiv.org/html/2605.29654v1), §§IV, V-A, V-B, V-D | Cryptographic device–MUD-class binding; profile changes use URL reissuance or signature-change detection and validation. | Profile authenticity and update propagation are complementary to the governance of independently approved traffic-derived facts. The inspected update workflow does not specify restoring a shared dispute while retaining an independent site veto. |

Interpretation: these differences position DIB's contribution at the interaction
of withdrawal, provenance and fresh approval. They do not imply that the other
systems could not be extended, that local policy sovereignty is new, or that DIB
replaces their authentication mechanisms. No published system is represented by
the experimental restoration adapters. The paper cites the works for their
positive mechanisms and avoids a blanket “first system” claim.

Dynamic blockchain MUD and other existing references are retained as background;
their full texts were not newly audited in this revision. No additional feature
absence or empirical comparison is attributed to them.
