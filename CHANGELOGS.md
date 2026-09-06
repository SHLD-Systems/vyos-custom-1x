# Changelog — `feature/SLA-WLB`

Branch off `rolling` at `16f1cf4` (merge `d47c5bd90`). Adds SLA-based dynamic weight adjustment to WAN load-balancing. CLA-style: proportional rules scale `base_weight * sla_factor` via latency/loss penalty; failover rules keep static boolean path (mutually exclusive).

## Commits (origin/rolling..HEAD)

- `7d145ef2c` first WLB SLA implementation
- `cfbb12d0e` Fixed unused import bug with old ping checking logic
- `468414c54` fixed SLA penalty with more accurate function and more knobs.
- `441f61b49` Added comments and minor fixes.
- `75bacf6d7` Revision of vmap assignment bug due to fractional SLA. Introduced normalized SLA effective weight assignment algorithm with edge case support
- `d47c5bd90` Merge branch 'rolling' into feature/SLA-WLB

## Files touched (7) — `git diff origin/rolling..HEAD --stat` 460 insertions, 40 deletions

### 1. `interface-definitions/load-balancing_wan.xml.in` (+59, 2 comments)
- New `load-balancing wan interval` leaf `u32:1-4294967295` default `5` — drives daemon loop `sleep_interval`, replaces hardcoded `5` (`src/helpers/vyos-load-balancer.py:363`).
- New `interface-health <ifname> sla` node with three leaves:
  - `max-latency` `1-10000` default `200` ms (H threshold)
  - `max-loss` `1-100` default `100` % (M threshold, stored `%` -> `M/100` ratio)
  - `penalty-baseline` `1-99` default `50` % (C scaling factor)
- All three carry `numeric` validators; documented as inputs to `sla_penalty` hyperbolic curve.

### 2. `interface-definitions/include/version/wanloadbalance-version.xml.i` (4→5)
- Bumped `<syntaxVersion component='wanloadbalance' version='5'>` with comment explaining SLA addition; paired with no-op migration.

### 3. `python/vyos/wanloadbalance.py` (+174, reworked `wlb_weight_interfaces`)
- Imports: added `re`, `rc_cmd` for ping parsing.
- `nft_rule` comment: weight path now SLA-aware (`wlb_weight_interfaces` returns normalized bins).
- `wlb_weight_interfaces` — full rewrite:
  - Failover: ignores SLA, returns highest static `base_weight` single jump.
  - Proportional: `eff = base_weight * sla_factor` (`sla_factor = 1 - penalty` clamp 0..1), single active always `[(ifname,"0")]` (100 %), multiple actives normalized by `max_eff` into 10 bins `bins=int(norm*10+0.5)`, `<0.05` filtered to 0, fallbacks for `max_eff==0` or empty.
  - Returns `[(ifname, "start-end"|"start")], total_weight` for `numgen random mod total vmap`.
- New `sla_penalty(latency,loss,H,M,C)` — piecewise `y=1 if L>=H or l>=M else min((1/(1-l/M)*H/(H-L))*C/100,1)` clamped 0..1; hyperbolic near thresholds, C independent.
- New `sla_factor_from_penalty` — `1-penalty` clamped 0..1.
- New `sla_effective_weight` helper for tests (rounded half-up, floor 0).
- New `_parse_ping_output` — parses iputils `"% packet loss"` + `"rtt ... = min/avg/max/mdev"` to `(loss_ratio 0..1, avg_rtt ms)`.
- New `health_ping_host_metrics(host,ifname,count=3,wait_time=5)` — 3-probe granularity, success=`rc==0 and loss<1.0`, returns `(success,loss,avg_rtt,rc,out)`.
- Retained legacy `health_ping_host` (1 probe) for compat + `health_ping_host_ttl`.

### 4. `src/helpers/vyos-load-balancer.py` (+212)
- Imports: swapped `health_ping_host`→`health_ping_host_metrics`, added `sla_penalty`/`sla_factor_from_penalty`.
- New `sla_compute(ifname,health_conf,latency,loss)` — resolves per-if `sla` thresholds with defaults `H200/M100/C50`, clamps `C1..99`, calls `sla_penalty`/`factor`, returns `{m,m_ratio,h,c,h_percent,m_percent,latency,loss,penalty,factor}` (aliases for template).
- `health_check` extended: preserves boolean `ACTIVE/FAILED` counting, but collects SLA metrics:
  - No IPv4 → `sla_loss=1.0` `factor=0.0` hardcoded FAILED.
  - No `test` → metrics ping against `nexthop` (dhcp resolved) `count=3`.
  - With `test` list: `ping` uses metrics (avg latency, max loss), `ttl`/`user-defined` boolean only; after loop updates `state['sla_*']` or inits `factor 1.0` if only non-ping tests.
- Startup: reads `lb.get('interval',5)` clamped `1..4294967295` to override module `sleep_interval`; initializes `health_state[ifname]` with `sla_factor 1.0/penalty 0.0/latency 0/loss 0/sla_m/h/c/sla_weight_changed False`.
- Main loop: tracks `old_factor`→`new_factor` drift `>0.01` → `sla_weight_changed`; `init` forces both `state_changed`+`sla_weight_changed`; triggers `nftables_update` on either boolean or SLA drift, writes `/run/wlb_status.json` on both paths (previously only on state change) plus `ip_change` path now also writes status.

### 5. `src/conf_mode/load-balancing_wan.py` (+22)
- `verify`: added SLA checks for `max_latency 1..10000`, `max_loss 1..100`, `penalty_baseline 1..99` with per-interface `ConfigError`; clarifying comment that XML validators already cover but verify gives clearer errors.

### 6. `src/op_mode/load-balancing_wan.py` (+25)
- `status_format` extended with `SLA Latency ms (H=...)`, `SLA Loss % (M=...)`, `SLA Baseline %`, `SLA Penalty`, `SLA Factor`/`Effective Weight Factor` (duplicate key, intentional alias).
- `_get_formatted_output`: `sla_loss` stored `0..1` ratio displayed `*100` (fallback if `>1` already %), `sla_latency .2f`, `penalty/factor .3f`, defaults `sla_m 100/h200/c50`.

### 7. `src/migration-scripts/wanloadbalance/4-to-5` (+6, new)
- No-op migration for version `4→5`: existing configs valid, new `interval`/`sla.*` optional with defaults; placeholder `pass` with comment.
