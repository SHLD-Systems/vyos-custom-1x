#!/usr/bin/env python3
#
# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import re

from vyos.defaults import directories
from vyos.utils.process import rc_cmd
from vyos.utils.process import run

dhclient_lease = 'dhclient_{0}.lease'

def nft_rule(rule_conf, rule_id, local=False, exclude=False, limit=False, weight=None, health_state=None, action=None, restore_mark=False):
    output = []

    if 'inbound_interface' in rule_conf:
        ifname = rule_conf['inbound_interface']
        if local and not exclude:
            output.append(f'oifname != "{ifname}"')
        elif not local:
            output.append(f'iifname "{ifname}"')

    if 'protocol' in rule_conf and rule_conf['protocol'] != 'all':
        protocol = rule_conf['protocol']
        operator = ''

        if protocol[:1] == '!':
            operator = '!='
            protocol = protocol[1:]

        if protocol == 'tcp_udp':
            protocol = '{ tcp, udp }'

        output.append(f'meta l4proto {operator} {protocol}')

    for direction in ['source', 'destination']:
        if direction not in rule_conf:
            continue

        direction_conf = rule_conf[direction]
        prefix = direction[:1]

        if 'address' in direction_conf:
            operator = ''
            address = direction_conf['address']
            if address[:1] == '!':
                operator = '!='
                address = address[1:]
            output.append(f'ip {prefix}addr {operator} {address}')

        if 'port' in direction_conf:
            operator = ''
            port = direction_conf['port']
            if port[:1] == '!':
                operator = '!='
                port = port[1:]
            output.append(f'th {prefix}port {operator} {{ {port} }}')

        if 'group' in direction_conf:
                group = direction_conf['group']
                if 'address_group' in group:
                    group_name = group['address_group']
                    operator = ''
                    exclude = group_name[0] == "!"
                    if exclude:
                        operator = '!='
                        group_name = group_name[1:]
                    output.append(f'ip {prefix}addr {operator} @A_{group_name}')
                if 'network_group' in group:
                    group_name = group['network_group']
                    operator = ''
                    if group_name[0] == "!":
                        operator = '!='
                        group_name = group_name[1:]
                    output.append(f'ip {prefix}addr {operator} @N_{group_name}')
                # Generate firewall group domain-group
                if 'domain_group' in group:
                    group_name = group['domain_group']
                    operator = ''
                    if group_name[0] == '!':
                        operator = '!='
                        group_name = group_name[1:]
                    output.append(f'ip {prefix}addr {operator} @D_{group_name}')
                if 'port_group' in group:
                    proto = rule_conf['protocol']
                    group_name = group['port_group']

                    if proto == 'tcp_udp':
                        proto = 'th'

                    operator = ''
                    if group_name[0] == '!':
                        operator = '!='
                        group_name = group_name[1:]

                    output.append(f'{proto} {prefix}port {operator} @P_{group_name}')

    if 'source_based_routing' not in rule_conf and not restore_mark:
        output.append('ct state new')

    if limit and 'limit' in rule_conf and 'rate' in rule_conf['limit']:
        output.append(f'limit rate {rule_conf["limit"]["rate"]}/{rule_conf["limit"]["period"]}')
        if 'burst' in rule_conf['limit']:
            output.append(f'burst {rule_conf["limit"]["burst"]} packets')

    output.append('counter')

    if restore_mark:
        output.append('meta mark set ct mark')
    elif weight:
        # SLA-aware weight selection: wlb_weight_interfaces returns normalized bins
        # For proportional rules this reflects dynamic SLA factor (base* sla_factor normalized to 10 bins max)
        # For failover rules it returns single highest static weight. The caller then builds either
        # a vmap (multiple bins) or a direct jump.
        weights, total_weight = wlb_weight_interfaces(rule_conf, health_state)
        if len(weights) > 1: # Create weight-based verdict map
            vmap_str = ", ".join(f'{weight} : jump wlb_mangle_isp_{ifname}' for ifname, weight in weights)
            output.append(f'numgen random mod {total_weight} vmap {{ {vmap_str} }}')
        elif len(weights) == 1: # Jump to single ISP
            ifname, _ = weights[0]
            output.append(f'jump wlb_mangle_isp_{ifname}')
        else: # No healthy interfaces
            return ""
    elif action:
        output.append(action)

    return " ".join(output)

# WLB weight selection with SLA-aware proportional distribution and failover exclusivity.
# Proportional mode:
#   eff = base_weight * sla_factor  (sla_factor = 1 - penalty, 0..1, from sla_penalty)
#   Single active interface -> single bin "0" regardless of penalty (ensures 100% if only one left).
#   Multiple actives: normalize eff by max_eff (strongest interface =1.0), then bins = round(norm*10)
#   Threshold <0.05 norm (<0.5 bins) rounds to 0 and is filtered out, so fully penalized (penalty 1.0 -> factor 0)
#   gets no bins when at least one other active exists. Total = sum(bins) used for numgen mod.
#   If max_eff==0 (all factors 0) or after filtering none remain, fallback to first active single bin.
# Failover mode:
#   Completely ignores SLA factor, uses static base weights only and returns highest-weight active interface.
#   This keeps failover strictly boolean (health state) and makes SLA vs failover mutually exclusive as required.
# The function preserves backward compatibility when sla_factor is missing (defaults to 1.0).
def wlb_weight_interfaces(rule_conf, health_state):
    is_failover = 'failover' in rule_conf
    active = []
    for ifname, if_conf in rule_conf['interface'].items():
        if ifname in health_state and health_state[ifname]['state']:
            base_weight = int(if_conf.get('weight', 1))
            if is_failover:
                # Failover: ignore dynamic SLA, keep static configured weight for deterministic primary/backup selection
                active.append((ifname, float(base_weight), base_weight))
            else:
                # Proportional: scale base weight by dynamic SLA factor derived from latency/loss penalty
                sla_factor = health_state[ifname].get('sla_factor', 1.0)
                try:
                    sla_factor = float(sla_factor)
                except Exception:
                    sla_factor = 1.0
                sla_factor = max(0.0, min(sla_factor, 1.0))
                eff = float(base_weight) * sla_factor
                active.append((ifname, eff, base_weight))
    if not active:
        # No interface in ACTIVE boolean state -> no bins, traffic falls through to system default table
        return [], 0
    if len(active) == 1:
        # Single active interface always gets one bin (100% traffic) even if heavily penalized
        ifname, eff, base = active[0]
        return [(ifname, "0")], 1
    if is_failover:
        # Failover: return highest static weight among actives as single jump, no vmap
        interfaces = [(ifname, base) for ifname, eff, base in active]
        for ifpair in sorted(interfaces, key=lambda i: i[1], reverse=True):
            return [ifpair], ifpair[1]
    # Proportional SLA path: find strongest effective weight for normalization
    max_eff = max(eff for _, eff, _ in active)
    if max_eff <= 0:
        # All effective weights zero (all factors 0) -> fallback to first active to avoid blackhole
        ifname, eff, base = active[0]
        return [(ifname, "0")], 1
    binned = []
    for ifname, eff, base in active:
        # Normalize eff to strongest =1.0, then allocate 10 bins per 1.0 point (0.5 threshold)
        norm = eff / max_eff if max_eff else 0
        bins = int(norm * 10 + 0.5)
        if bins > 0:
            binned.append((ifname, bins))
    if not binned:
        # All norms <0.05 (bins 0) -> fallback to strongest factor single bin
        ifname, eff, base = max(active, key=lambda x: x[1])
        return [(ifname, "0")], 1
    binned_sorted = sorted(binned, key=lambda x: x[1])
    out = []
    start = 0
    total_weight = sum(b for _, b in binned_sorted)
    for ifname, bins in binned_sorted:
        end = start + bins - 1
        out.append((ifname, f'{start}-{end}' if end > start else str(start)))
        start += bins
    return out, total_weight

# SLA latency penalty function (piecewise) as specified in design:
#   if L >= H : y = 1  (latency at or beyond threshold -> maximal penalty)
#   if l >= M : y = 1  (loss at or beyond max loss -> maximal penalty)
#   else y = min( (1/(1 - l/M) * H/(H - L)) * C/100 , 1 )
# Where l=measured loss ratio 0..1, M=max loss ratio (max-loss%/100), L=measured latency ms,
# H=max latency ms (max-latency), C=penalty baseline 1..99 (C/100 scales baseline magnitude).
# H controls latency sensitivity (smaller H/L ratio -> steeper), M controls loss sensitivity,
# C controls baseline independently of thresholds. Result clamped 0..1.
def sla_penalty(latency, loss, H, M, C=50):
    if H <= 0 or M <= 0:
        return 1.0
    if loss < 0:
        loss = 0.0
    if latency < 0:
        latency = 0.0
    if latency >= H:
        return 1.0
    if loss >= M:
        return 1.0
    if C < 1:
        C = 1
    if C > 99:
        C = 99
    try:
        loss_component = 1.0 / (1.0 - loss / M)
        latency_component = H / (H - latency)
        penalty = loss_component * latency_component * (C / 100.0)
    except ZeroDivisionError:
        return 1.0
    if penalty > 1.0:
        penalty = 1.0
    if penalty < 0.0:
        penalty = 0.0
    return penalty

# Convert penalty 0..1 to forwarding factor 1..0 (factor = 1 - penalty). Used as eff = base * factor.
# Clamped to 0..1 to avoid negative/overflow weights.
def sla_factor_from_penalty(penalty):
    factor = 1.0 - penalty
    if factor < 0.0:
        factor = 0.0
    if factor > 1.0:
        factor = 1.0
    return factor

# Helper to compute effective weight from raw SLA measurements in one call (used for direct tests).
# Returns (weight, penalty, factor) with weight rounded half-up and floored at 0 to allow exclusion.
def sla_effective_weight(base_weight, latency, loss, H, M, C=50):
    penalty = sla_penalty(latency, loss, H, M, C)
    factor = sla_factor_from_penalty(penalty)
    weight = int(base_weight * factor + 0.5)
    if weight < 0:
        weight = 0
    return weight, penalty, factor

# Parse ping output for metrics: extracts loss ratio from "X% packet loss" and avg RTT from "rtt ... = min/avg/max/mdev".
# Returns (loss_ratio 0..1 or None, avg_rtt ms or None) for SLA penalty calculation. Regex tolerant to
# varying ping output locales/formats; caller falls back to rc-based defaults if parsing fails.
def _parse_ping_output(output):
    loss_ratio = None
    avg_rtt = None
    m_loss = re.search(r'(\d+(?:\.\d+)?)% packet loss', output)
    if m_loss:
        try:
            loss_ratio = float(m_loss.group(1)) / 100.0
        except ValueError:
            loss_ratio = None
    m_rtt = re.search(r'rtt [^\n]*= [\d\.]+/([\d\.]+)/[\d\.]+/[\d\.]+', output)
    if m_rtt:
        try:
            avg_rtt = float(m_rtt.group(1))
        except ValueError:
            avg_rtt = None
    return loss_ratio, avg_rtt

# Metrics-aware ping: runs "ping -c count -W wait_time -I ifname host" and parses packet loss and avg RTT.
# Uses count=3 by default to allow loss ratio granularity (0, 0.33, 0.66, 1.0) for SLA. Returns (success bool,
# loss_ratio, avg_rtt, rc, out). Success is rc==0 and loss<1.0 (at least one reply) – boolean health remains
# lenient so moderate loss reduces weight via SLA factor rather than immediately marking FAILED; full loss still
# drives penalty 1.0 and may be filtered to 0 bins in proportional mode.
def health_ping_host_metrics(host, ifname, count=3, wait_time=5):
    cmd_str = f'ping -c {count} -W {wait_time} -I {ifname} {host}'
    rc, out = rc_cmd(cmd_str)
    loss_ratio, avg_rtt = _parse_ping_output(out)
    if loss_ratio is None:
        loss_ratio = 0.0 if rc == 0 else 1.0
    if avg_rtt is None:
        avg_rtt = 0.0
    success = rc == 0 and loss_ratio < 1.0
    return success, loss_ratio, avg_rtt, rc, out

def health_ping_host(host, ifname, count=1, wait_time=0):
    cmd_str = f'ping -c {count} -W {wait_time} -I {ifname} {host}'
    rc = run(cmd_str)
    return rc == 0

def health_ping_host_ttl(host, ifname, count=1, ttl_limit=0):
    cmd_str = f'ping -c {count} -t {ttl_limit} -I {ifname} {host}'
    rc = run(cmd_str)
    return rc != 0

def parse_dhcp_nexthop(ifname):
    lease_file = os.path.join(directories['isc_dhclient_dir'], dhclient_lease.format(ifname))

    if not os.path.exists(lease_file):
        return False

    with open(lease_file, 'r') as f:
        for line in f.readlines():
            data = line.replace('\n', '').split('=')
            if data[0] == 'new_routers':
                return data[1].replace("'", '').split(" ")[0]

    return None

def parse_ppp_nexthop(ifname):
    nexthop_file = os.path.join(directories['ppp_nexthop_dir'], ifname)

    if not os.path.exists(nexthop_file):
        return False

    with open(nexthop_file, 'r') as f:
        return f.read()
