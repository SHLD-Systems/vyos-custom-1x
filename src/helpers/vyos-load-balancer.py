#!/usr/bin/python3

# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/>.

import json
import os
import signal
import sys
import time

from vyos.config import Config
from vyos.template import render
from vyos.utils.commit import commit_in_progress
from vyos.utils.dict import dict_search_args
from vyos.utils.network import get_interface_address
from vyos.utils.process import rc_cmd
from vyos.utils.process import run
from vyos.xml_ref import get_defaults
# SLA-aware imports: metrics ping provides loss/latency for penalty; sla_penalty computes
# piecewise latency penalty y = min((1/(1-l/M)*H/(H-L))*C/100,1) if L<H else 1
from vyos.wanloadbalance import health_ping_host_metrics
from vyos.wanloadbalance import health_ping_host_ttl
from vyos.wanloadbalance import parse_dhcp_nexthop
from vyos.wanloadbalance import parse_ppp_nexthop
from vyos.wanloadbalance import sla_factor_from_penalty
from vyos.wanloadbalance import sla_penalty

nftables_wlb_conf = '/run/nftables_wlb.conf'
wlb_status_file = '/run/wlb_status.json'
wlb_pid_file = '/run/wlb_daemon.pid'
# Default health check loop interval seconds; overridden at startup from global
# load-balancing wan interval leaf (u32:1-4294967295, default 5) via get_config()
sleep_interval = 5
SLA_FACTOR_DELTA_THRESHOLD=0.05

# Compute SLA penalty/factor for an interface from measured latency/loss and configured thresholds.
# H = max-latency ms (per-interface sla max-latency), M = max-loss ratio (max-loss%/100),
# C = penalty baseline 1..99 (penalty-baseline). Handles missing config via defaults (H200,M100%,C50)
# and None measurements (falls back to H or 0). Returns dict with raw thresholds, measurements,
# penalty 0..1 and factor 0..1 (factor = 1 - penalty) used as eff = base_weight * factor in wlb_weight_interfaces.
def sla_compute(ifname, health_conf, latency_ms, loss_ratio):
    sla_conf = health_conf.get('sla', {})
    try:
        h_val = int(sla_conf.get('max_latency', 200))
    except Exception:
        h_val = 200
    try:
        m_percent = int(sla_conf.get('max_loss', 100))
    except Exception:
        m_percent = 100
    try:
        c_val = int(sla_conf.get('penalty_baseline', 50))
    except Exception:
        c_val = 50
    if c_val < 1:
        c_val = 1
    if c_val > 99:
        c_val = 99
    m_ratio = m_percent / 100.0
    if m_ratio <= 0:
        m_ratio = 1.0
    if m_ratio > 1.0:
        m_ratio = 1.0
    if loss_ratio is None:
        loss_ratio = 0.0
    if latency_ms is None:
        latency_ms = float(h_val)
    penalty = sla_penalty(float(latency_ms), float(loss_ratio), float(h_val), float(m_ratio), int(c_val))
    factor = sla_factor_from_penalty(penalty)
    return {
        'm': m_percent,
        'm_ratio': m_ratio,
        'h': h_val,
        'c': c_val,
        'h_percent': h_val,
        'm_percent': m_percent,
        'latency': float(latency_ms),
        'loss': float(loss_ratio),
        'penalty': float(penalty),
        'factor': float(factor),
    }

# Extended health check that preserves original boolean ACTIVE/FAILED logic (failure_count/success_count)
# while also collecting SLA metrics (avg RTT and loss ratio) via ping for penalty calculation.
# No-address -> immediate FAILED with sla_loss 1.0 and factor 0.0.
# No test configured -> ping nexthop (static or dhcp) with metrics.
# With test list: ping type uses health_ping_host_metrics (3 packets, averages latency, max loss),
# ttl/user-defined remain boolean only; after loop SLA state is updated from collected metrics
# (or fallback to 0/0 -> factor 1.0 / no SLA penalization if only non-ping tests). Returns boolean overall_success for
# failure/success threshold counting, while side-effect updates state['sla_*'] used by wlb_weight_interfaces.
def health_check(ifname, conf, state, test_defaults):
    if get_ipv4_address(ifname) is None:
        state['sla_latency'] = 0.0
        state['sla_loss'] = 1.0
        sla_res = sla_compute(ifname, conf, state['sla_latency'], state['sla_loss'])
        state['sla_penalty'] = sla_res['penalty']
        state['sla_factor'] = 0.0
        state['sla_m'] = sla_res['m']
        state['sla_h'] = sla_res['h']
        state['sla_c'] = sla_res['c']
        return False

    collected_latency = None
    collected_loss = None

    # No test configured -> ping nexthop (dhcp resolved) with metrics for SLA, boolean success for threshold
    if 'test' not in conf:
        resp_time = test_defaults['resp-time']
        target = conf['nexthop']
        if target == 'dhcp':
            target = state['dhcp_nexthop']
        if not target:
            return False
        success, loss_ratio, avg_rtt, rc, out = health_ping_host_metrics(target, ifname, count=3, wait_time=resp_time)
        collected_latency = avg_rtt if avg_rtt is not None else 0.0
        collected_loss = loss_ratio if loss_ratio is not None else (0.0 if success else 1.0)
        state['sla_latency'] = float(collected_latency)
        state['sla_loss'] = float(collected_loss)
        sla_res = sla_compute(ifname, conf, collected_latency, collected_loss)
        state['sla_penalty'] = sla_res['penalty']
        state['sla_factor'] = sla_res['factor']
        state['sla_m'] = sla_res['m']
        state['sla_h'] = sla_res['h']
        state['sla_c'] = sla_res['c']
        return success

    # With tests configured: ping type uses health_ping_host_metrics (3 packets, averages latency, max loss),
    # ttl/user-defined remain boolean only; after loop SLA state is updated from collected metrics
    overall_success = True

    for test_id, test_conf in conf['test'].items():
        check_type = test_conf['type']
        if check_type == 'ping':
            # Use metrics ping for SLA (3 packets) while retaining boolean success for health threshold
            resp_time = test_conf['resp_time']
            target = test_conf['target']
            success, loss_ratio, avg_rtt, rc, out = health_ping_host_metrics(target, ifname, count=3, wait_time=resp_time)
            if collected_latency is None:
                collected_latency = avg_rtt if avg_rtt is not None else 0.0
                collected_loss = loss_ratio if loss_ratio is not None else (0.0 if success else 1.0)
            else:
                if avg_rtt is not None:
                    collected_latency = (collected_latency + avg_rtt) / 2.0
                if loss_ratio is not None:
                    collected_loss = max(collected_loss, loss_ratio)
            if not success:
                overall_success = False

        elif check_type == 'ttl':
            target = test_conf['target']
            ttl_limit = test_conf['ttl_limit']
            if not health_ping_host_ttl(target, ifname, ttl_limit=ttl_limit):
                overall_success = False

        elif check_type == 'user-defined':
            script = test_conf['test_script']
            env = os.environ.copy()
            env.update(
                {
                    'WLB_INTERFACE_NAME': ifname,
                    'WLB_SCRIPT_IFACE': ifname,
                }
            )
            rc = run(script, env=env)
            if rc != 0:
                overall_success = False

    if collected_latency is not None and collected_loss is not None:
        # At least one ping test provided metrics -> update SLA with averaged/worst values
        state['sla_latency'] = float(collected_latency)
        state['sla_loss'] = float(collected_loss)
        sla_res = sla_compute(ifname, conf, collected_latency, collected_loss)
        state['sla_penalty'] = sla_res['penalty']
        state['sla_factor'] = sla_res['factor']
        state['sla_m'] = sla_res['m']
        state['sla_h'] = sla_res['h']
        state['sla_c'] = sla_res['c']
    else:
        # No ping metrics (only ttl/user-defined) -> preserve or init factor 1.0 (no SLA impact)
        if 'sla_factor' not in state:
            state['sla_factor'] = 1.0
            state['sla_penalty'] = 0.0
            state['sla_latency'] = 0.0
            state['sla_loss'] = 0.0
            sla_res = sla_compute(ifname, conf, 0.0, 0.0)
            state['sla_m'] = sla_res['m']
            state['sla_h'] = sla_res['h']
            state['sla_c'] = sla_res['c']

    return overall_success

def on_state_change(lb, ifname, state):
    # Run hook on state change
    if 'hook' in lb:
        script_path = os.path.join('/config/scripts/', lb['hook'])
        env = {
            'WLB_INTERFACE_NAME': ifname,
            'WLB_INTERFACE_STATE': 'ACTIVE' if state else 'FAILED'
        }

        code = run(script_path, env=env)
        if code != 0:
            print('WLB hook returned non-zero error code')

    print(f'INFO: State change: {ifname} -> {state}')

def get_ipv4_address(ifname):
    # Get primary ipv4 address on interface (for source nat)
    addr_json = get_interface_address(ifname)
    if addr_json and 'addr_info' in addr_json and len(addr_json['addr_info']) > 0:
        for addr_info in addr_json['addr_info']:
            if addr_info['family'] == 'inet':
                if 'local' in addr_info:
                    return addr_json['addr_info'][0]['local']
    return None

def get_dynamic_nexthop(ifname: str) -> str | None | bool:
    '''
    Resolve the dynamic next-hop for a WAN interface.

    Determines the current default gateway learned dynamically on the interface:
    - PPPoE interfaces (`pppoe*`): uses `parse_ppp_nexthop`.
    - Other interfaces (e.g. DHCP): uses `parse_dhcp_nexthop`.

    Return values:
    - str: IPv4 next-hop address
    - None: when DHCP lease has no router value
    - False: when PPPoE nexthop state file is missing

    Args:
        ifname: Interface name (e.g. 'pppoe0', 'eth0').

    Returns:
        See above for possible values.
    '''
    if ifname.startswith('pppoe'):
        return parse_ppp_nexthop(ifname)
    else:
        return parse_dhcp_nexthop(ifname)

def dynamic_nexthop_update(lb, ifname):
    # Update on DHCP/PPP address/nexthop changes
    # Return True if nftables needs to be updated - IP change

    if 'dhcp_nexthop' in lb['health_state'][ifname]:
        dhcp_nexthop_addr = get_dynamic_nexthop(ifname)

        table_num = lb['health_state'][ifname]['table_number']

        if dhcp_nexthop_addr and lb['health_state'][ifname]['dhcp_nexthop'] != dhcp_nexthop_addr:
            lb['health_state'][ifname]['dhcp_nexthop'] = dhcp_nexthop_addr
            run(f'ip route replace table {table_num} default dev {ifname} via {dhcp_nexthop_addr}')

    if_addr = get_ipv4_address(ifname)
    if if_addr and if_addr != lb['health_state'][ifname]['if_addr']:
        lb['health_state'][ifname]['if_addr'] = if_addr
        return True

    return False

def restore_default_route(lb: dict, ifname: str) -> None:
    """
    Restores a missing default route for a WAN interface in its policy routing table.

    When a link flap or DHCP/PPP renegotiation removes the per-interface default route,
    this function checks the interface’s assigned table for an existing default entry.
    If none is found, it determines the proper next-hop (from DHCP, PPP, or static config)
    and reinstalls the route using:
      ip route replace table <table_num> default dev <ifname> via <nexthop>

    @param lb       Load-balancer state/config dictionary.
    @param ifname   Interface name whose default route should be verified and restored.
    @returns        None — exits quietly if the table number or next-hop cannot be found.
    """
    table_num = dict_search_args(lb, 'health_state', ifname, 'table_number')
    if not table_num:
        return

    rc, out = rc_cmd(f'ip -j route show default table {table_num}')
    if rc == 0:
        rt_table = json.loads(out)
        if len(rt_table) > 0:
            return
        else:
            if 'dhcp_nexthop' in lb['health_state'][ifname]:
                nexthop_addr = get_dynamic_nexthop(ifname)
            else:
                nexthop_addr = dict_search_args(lb, 'interface_health', ifname, 'nexthop')

            if nexthop_addr:
                run(f'ip route replace table {table_num} default dev {ifname} via {nexthop_addr}')
    else:
        return

def nftables_update(lb):
    # Atomically reload nftables table from template
    if not os.path.exists(nftables_wlb_conf):
        lb['first_install'] = True
    elif 'first_install' in lb:
        del lb['first_install']

    render(nftables_wlb_conf, 'load-balancing/nftables-wlb.j2', lb)

    rc, out = rc_cmd(f'nft -f {nftables_wlb_conf}')

    if rc != 0:
        print('ERROR: Failed to apply WLB nftables config')
        print('Output:', out)
        return False

    return True

def cleanup(lb):
    if 'interface_health' in lb:
        index = 1
        for ifname, health_conf in lb['interface_health'].items():
            table_num = lb['mark_offset'] + index
            suppress_prio = lb['mark_offset'] + index
            table_prio = suppress_prio + 100
            run(f'ip route del table {table_num} default')
            run(
                f'ip rule del fwmark {hex(table_num)} table main '
                f'suppress_prefixlength 0 priority {suppress_prio}'
            )
            run(
                f'ip rule del fwmark {hex(table_num)} table {table_num} '
                f'priority {table_prio}'
            )
            run(f'ip rule del fwmark {hex(table_num)} table {table_num}')
            index += 1

    run(f'nft delete table ip vyos_wanloadbalance')

def get_config():
    conf = Config()
    base = ['load-balancing', 'wan']
    lb = conf.get_config_dict(base, key_mangling=('-', '_'),
                            get_first_key=True, with_recursive_defaults=True)

    lb['firewall_group'] = conf.get_config_dict(['firewall', 'group'], key_mangling=('-', '_'), get_first_key=True,
                                    no_tag_node_value_mangle=True)

    # prune limit key if not set by user
    for rule in lb.get('rule', []):
        if lb.from_defaults(['rule', rule, 'limit']):
            del lb['rule'][rule]['limit']

    lb['test_defaults'] = get_defaults(base + ['interface-health', 'A', 'test', 'B'], get_first_key=True)

    return lb

if __name__ == '__main__':
    while commit_in_progress():
        print("Notice: Waiting for commit to complete...")
        time.sleep(1)

    lb = get_config()
    # Global health check interval from load-balancing wan interval (1..4294967295, default 5)
    # Overrides the module-level sleep_interval so daemon loop respects configured period
    # without requiring code change; clamped to valid range.
    try:
        sleep_interval = int(lb.get('interval', 5))
        if sleep_interval < 1:
            sleep_interval = 1
        if sleep_interval > 4294967295:
            sleep_interval = 4294967295
    except Exception:
        sleep_interval = 5

    lb['health_state'] = {}
    lb['mark_offset'] = 0xc8

    # Create state dicts, interface address and nexthop, install routes and ip rules
    # Extended to include SLA state (factor/penalty/latency/loss/thresholds) for dynamic weight
    # and sla_weight_changed flag for vmap rebuild detection. This keeps old boolean state
    # (state, failure/success counts) and new SLA state in parallel as required for mixed
    # failover (static) vs proportional (SLA) rules.
    if 'interface_health' in lb:
        index = 1
        for ifname, health_conf in lb['interface_health'].items():
            table_num = lb['mark_offset'] + index
            addr = get_ipv4_address(ifname)
            sla_conf = health_conf.get('sla', {})
            try:
                sla_h = int(sla_conf.get('max_latency', 200))
            except Exception:
                sla_h = 200
            try:
                sla_m = int(sla_conf.get('max_loss', 100))
            except Exception:
                sla_m = 100
            try:
                sla_c = int(sla_conf.get('penalty_baseline', 50))
            except Exception:
                sla_c = 50
            if sla_c < 1:
                sla_c = 1
            if sla_c > 99:
                sla_c = 99
            lb['health_state'][ifname] = {
                'if_addr': addr,
                'failure_count': 0,
                'success_count': 0,
                'last_success': 0,
                'last_failure': 0,
                'state': addr is not None,
                'state_changed': False,
                'table_number': table_num,
                'mark': hex(table_num),
                'sla_factor': 1.0,
                'sla_penalty': 0.0,
                'sla_latency': 0.0,
                'sla_loss': 0.0,
                'sla_m': sla_m,
                'sla_h': sla_h,
                'sla_c': sla_c,
                'sla_weight_changed': False,
            }

            if health_conf['nexthop'] == 'dhcp':
                lb['health_state'][ifname]['dhcp_nexthop'] = None

                dynamic_nexthop_update(lb, ifname)
            else:
                run(f'ip route replace table {table_num} default dev {ifname} via {health_conf["nexthop"]}')

            suppress_prio = lb['mark_offset'] + index
            table_prio = suppress_prio + 100
            if 'only_default_route' in lb:
                run(
                    f'ip rule add fwmark {hex(table_num)} table main '
                    f'suppress_prefixlength 0 priority {suppress_prio}'
                )
                run(
                    f'ip rule add fwmark {hex(table_num)} table {table_num} '
                    f'priority {table_prio}'
                )
            else:
                run(f'ip rule add fwmark {hex(table_num)} table {table_num}')

            index += 1

        nftables_update(lb)

        run('ip route flush cache')

        if 'flush_connections' in lb:
            for _state in lb['health_state'].values():
                run(f'conntrack --delete --mark {_state["table_number"]}')

        with open(wlb_status_file, 'w') as f:
            f.write(json.dumps(lb['health_state']))

    # Signal handler SIGUSR2 -> dhcpcd update
    def handle_sigusr2(signum, frame):
        for ifname, health_conf in lb['interface_health'].items():
            if 'nexthop' in health_conf and health_conf['nexthop'] == 'dhcp':
                retval = dynamic_nexthop_update(lb, ifname)

                if retval:
                    nftables_update(lb)

    # Signal handler SIGTERM -> exit
    def handle_sigterm(signum, frame):
        if os.path.exists(wlb_status_file):
            os.unlink(wlb_status_file)

        if os.path.exists(wlb_pid_file):
            os.unlink(wlb_pid_file)

        if os.path.exists(nftables_wlb_conf):
            os.unlink(nftables_wlb_conf)

        cleanup(lb)
        sys.exit(0)

    signal.signal(signal.SIGUSR2, handle_sigusr2)
    signal.signal(signal.SIGINT, handle_sigterm)
    signal.signal(signal.SIGTERM, handle_sigterm)

    with open(wlb_pid_file, 'w') as f:
        f.write(str(os.getpid()))

    # Main loop
    # Tracks both boolean state changes (failure/success thresholds) and SLA factor changes (>0.01)
    # to decide when to rebuild nftables vmap and flush conntrack. Parallel tracking preserves
    # old ACTIVE/FAILED state machine while adding dynamic weight distribution. First iteration
    # forces state_changed and sla_weight_changed to install initial vmap. Fallback handling
    # ensures single active interface always gets a bin even if heavily penalized.

    init = True;
    sla_factor_map = { ifname: 0 for ifname in lb['interface_health'].keys() }
    try:
        while True:
            ip_change = False
            sla_weight_changed = False

            if 'interface_health' in lb:
                for ifname, health_conf in lb['interface_health'].items():
                    state = lb['health_state'][ifname]

                    # Track SLA factor changes to trigger vmap rebuild if >0.01 drift from previous value
                    old_factor = sla_factor_map[ifname]

                    # Run the health checks for the interface based on configured tests. Update state.
                    result = health_check(ifname, health_conf, state=state, test_defaults=lb['test_defaults'])

                    # Update SLA factor map and detect meaningful drift to avoid flapping on tiny RTT jitter
                    new_factor = state.get('sla_factor', 1.0)
                    if abs(new_factor - old_factor) > SLA_FACTOR_DELTA_THRESHOLD:
                        sla_factor_map[ifname] = new_factor
                        state['sla_weight_changed'] = True
                        sla_weight_changed = True
                    else:
                        state['sla_weight_changed'] = False

                    state_changed = result != state['state']
                    state['state_changed'] = False

                    if result:
                        state['failure_count'] = 0
                        state['success_count'] += 1
                        state['last_success'] = time.time()
                        if state_changed and state['success_count'] >= int(health_conf['success_count']):
                            state['state'] = True
                            state['state_changed'] = True
                    elif not result:
                        state['failure_count'] += 1
                        state['success_count'] = 0
                        state['last_failure'] = time.time()
                        if state_changed and state['failure_count'] >= int(health_conf['failure_count']):
                            state['state'] = False
                            state['state_changed'] = True

                    if init == True:
                        state['state_changed'] = True
                        sla_weight_changed = True
                    if state['state_changed']:
                        state['if_addr'] = get_ipv4_address(ifname)
                        on_state_change(lb, ifname, state['state'])

                    if dynamic_nexthop_update(lb, ifname):
                        ip_change = True

                    restore_default_route(lb, ifname)

                if init == True:
                    init = False

            if any(state['state_changed'] for ifname, state in lb['health_state'].items()) or sla_weight_changed:
                if not nftables_update(lb):
                    break

                run('ip route flush cache')

                if 'flush_connections' in lb:
                    for _state in lb['health_state'].values():
                        run(f'conntrack --delete --mark {_state["table_number"]}')

                with open(wlb_status_file, 'w') as f:
                    f.write(json.dumps(lb['health_state']))
            elif ip_change:
                nftables_update(lb)
                with open(wlb_status_file, 'w') as f:
                    f.write(json.dumps(lb['health_state']))

            time.sleep(sleep_interval)
    except Exception as e:
        print('WLB ERROR:', e)

    if os.path.exists(wlb_status_file):
        os.unlink(wlb_status_file)

    if os.path.exists(wlb_pid_file):
        os.unlink(wlb_pid_file)

    if os.path.exists(nftables_wlb_conf):
            os.unlink(nftables_wlb_conf)

    cleanup(lb)
