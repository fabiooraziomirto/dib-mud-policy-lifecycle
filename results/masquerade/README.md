# Experiment 22 — Adversarial service masquerading against the typed filter

Closes the reviewer TODO on `main_v5.0.tex:326`: the resolved-domain Sybil
stress test attacks the *score*, so it never tested the cheapest way across the
*eligibility filter*. The supervisor raised the same point during the July
review (`comments.txt:1802`): "Usare le porte per classificare il traffico non
ci apre ancora più facilmente ad essere avvelenati?"

## The mechanism

`intent_overlap.classify_core` assigns DNS and NTP by **protocol OR port**,
with no payload validation, after an address-scope veto that only rejects
*non-global* IP literals:

```python
if parsed_ip is not None and not parsed_ip.is_global: return "other"
if protocol == "dns" or port == 53:  return "dns"
if protocol == "ntp" or port == 123: return "ntp"
```

An **unresolved but globally-scoped IP literal** therefore becomes
class-eligible purely by choosing destination port 53 or 123. No DNS or NTP
message is ever required. This matters because the A1 result rests on captured
attack traffic being excluded by exactly this filter: that exclusion is a
property of the trace's port numbers, not of the defence.

## Setup

```bash
cd reproducibility/code
python3 scripts/service_masquerade_probe.py
```

Everything is held fixed except the destination port: same injector
(`inject_persistent_fake_endpoint`), same template observations, same frozen
operating point (0.6, 0.4, 0.0, θ=0.65, m=2, trust-weighted), same seed 42, same
10 pseudo-sites. Port 443 is the control — identical traffic, ineligible class.

Endpoint: `192.88.99.11`, inside the deprecated 6to4 relay anycast prefix
(RFC 7526). It satisfies `ipaddress.is_global` — which is what the filter tests
— while being assigned to no real host. No packet is sent anywhere; the
experiment is an offline transformation of the observation CSV.

Reported per cell: the highest-scoring instance that also clears the
corroboration quorum (the attacker's best realizable shot), not the global
maximum.

## Result

| Port | f | D=1 | D=30 | D=120 | Class |
|---|---|---|---|---|---|
| 53 (DNS) | 0.30 | 0.354 | 0.529 | 0.562 | eligible |
| 53 (DNS) | 0.50 | 0.487 | **0.663 admitted** | **0.688 admitted** | eligible |
| 123 (NTP) | 0.30 | 0.354 | 0.529 | 0.562 | eligible |
| 123 (NTP) | 0.50 | 0.487 | **0.663 admitted** | **0.688 admitted** | eligible |
| 443 (control) | 0.30/0.50 | same scores | same scores | same scores | **ineligible** |

Two findings, and the second is the one that belongs in the paper:

1. **The typed filter provides no defence against port masquerading.** In all 12
   port-53/123 cells the fabricated endpoint is class-eligible, with an
   unresolved IP literal as its peer. The control cells carry *identical*
   scores and are stopped by the filter alone. The only difference is the
   destination port number.
2. **At the declared stress-test budget the fabrication is still rejected — by
   the score, not by the filter.** At f=0.30 the best quorum-clearing score is
   0.562 < θ=0.65, consistent with Criterion 1's bound
   (0.6·0.30 + 0.4 = 0.58 < 0.65). At f=0.50 the criterion offers no guarantee
   at all (bound 0.70 > θ), and the measurement agrees: sustained masquerading
   at 30 days or more is admitted at 0.663.

So the masquerading result does not contradict Criterion 1 — it lands exactly
where the criterion says it should. What it removes is the implicit claim that
the eligibility filter contributes security against a bounded poisoner: it does
not. Staged facts remain unenforced pending local commit, which is where the
authorization boundary actually holds.

## Provenance

`manifest.json` records `input_sha256` of the observation CSV, the endpoint
rationale, the port cases, the operating point, and the injector used.
