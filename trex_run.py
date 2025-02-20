#!/usr/bin/env python3

import sys

sys.path.insert(0, "/opt/trex/automation/trex_control_plane/interactive/trex/examples/astf")
import argparse
import os
import re
import time
import astf_path
import socket
import threading
import signal
import logging
import json

from copy import deepcopy
from itertools import cycle
from trex.astf.api import ASTFProfile, TRexError, TRexTimeoutError, ASTFClient
from influxdb import InfluxDBClient
from distutils import util
from flatten_json import flatten

SCRIPT_ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
SINGLE_ATTACK_PROFILE = os.path.join(SCRIPT_ROOT_PATH, 'trex_profiles', 'attack_single.py')
MAIN_PROFILE_ID = 'main_profile'
ATTACK_PROFILE_ID = 'attack_profile_{0}'
MAIN_STATS = {'m_traffic_duration': 'workload duration (sec)',
              'udps_sndbyte': 'UDP TX bytes',
              'udps_rcvbyte': 'UDP RX bytes',
              'udps_sndpkt': 'UDP TX packets',
              'udps_rcvpkt': 'UDP RX packets',
              'udps_keepdrops': 'UDP session drops',
              'udps_accepts': 'UDP connections accepted',
              'udps_connects': 'UDP connections established',
              'udps_closed': 'UDP conn. closed (including drops)',
              'tcps_connects': 'TCP connections established',
              'tcps_closed': 'TCP conn. closed (including drops)',
              'tcps_sndtotal': 'TCP TX packets',
              'tcps_sndbyte': 'TCP TX bytes',
              'tcps_rcvtotal': 'TCP RX packets',
              'tcps_rcvbyte': 'TCP RX bytes',
              'tcps_drops': 'TCP session drops',
              'm_tx_ratio': 'TX bw vs retransmits bw',
              'm_avg_size': 'Avg packet size bytes',
              }

DEBUG_STATS = ['err_c_nf_throttled',
               'err_c_tuple_err',
               'err_cwf',
               'err_dct',
               'err_defer_no_template',
               'err_flow_overflow',
               'err_fragments_ipv4_drop',
               'err_l3_cs',
               'err_l4_cs',
               'err_len_err',
               'err_no_memory',
               'err_no_syn',
               'err_no_tcp_udp',
               'err_no_template',
               'err_redirect_rx',
               'err_rx_throttled',
               'err_s_nf_throttled',
               'flows_other',
               'ignored_ips',
               'ignored_macs',
               'rss_redirect_drops',
               'rss_redirect_queue_full',
               'rss_redirect_rx',
               'rss_redirect_tx',
               'tcps_badsyn',
               'tcps_conndrops',
               'tcps_delack',
               'tcps_keepdrops',
               'tcps_keeptimeo',
               'tcps_nombuf',
               'tcps_pawsdrop',
               'tcps_persistdrop',
               'tcps_persisttimeo',
               'tcps_rcvafterclose',
               'tcps_rcvbadoff',
               'tcps_rcvbadsum',
               'tcps_rcvpackafterwin',
               'tcps_rcvdupack',
               'tcps_rcvduppack',
               'tcps_rcvoffloads',
               'tcps_rcvoopack',
               'tcps_rcvoopackdrop',
               'tcps_rcvshort',
               'tcps_rcvwinupd',
               'tcps_rexmttimeo',
               'tcps_rexmttimeo_syn',
               'tcps_sndrexmitpack',
               'tcps_sndurg',
               'tcps_sndwinup',
               'tcps_testdrops',
               'tcps_timeoutdrop',
               'udps_nombuf',
               'udps_pkt_toobig',
               'tcps_connattempt',
               'tcps_testdrops',
               ]
# retry counts to start trex
RETRY = 5

KPI_GLOBAL = {
    'tx_bps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'rx_bps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'tx_pps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'rx_pps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'active_flows': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'tx_cps': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'queue_full': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    },
    'cpu_util': {
        'sum': 0.0,
        'count': 0,
        'avg': 0.0
    }
}

GRAFANA_DASHBOARDS_NGFW = [
    'pt-ngfw',
    'linux',
]

GRAFANA_DASHBOARDS_TREX = [
    'cisco-trex',
]

DEFAULT_TIMEOUT_SEC = 100


class Keyvalue(argparse.Action):
    # Constructor calling
    def __call__(self, parser, namespace,
                 values, option_string=None):
        setattr(namespace, self.dest, dict())

        for value in values:
            # split it into key and value
            key, value = value.split('=')
            # assign into dictionary
            getattr(namespace, self.dest)[key] = value


def grafana_url(host, from_time, to_time, trex, test_id, ngfw_host):
    time_offset = 10_000  # 10 Seconds time offset
    grafana_url_sample = "{0}/d/{1}/{1}?var-hostname={2}&var-test_id={3}&from={4}&to={5}"
    dashboards = {}
    if ngfw_host:
        for dash in GRAFANA_DASHBOARDS_NGFW:
            dashboards[dash] = grafana_url_sample.format(host, dash, ngfw_host, test_id,
                                                         from_time - time_offset, to_time + time_offset)
    for dash in GRAFANA_DASHBOARDS_TREX:
        dashboards[dash] = grafana_url_sample.format(host, dash, trex, test_id,
                                                     from_time - time_offset, to_time + time_offset)

    return dashboards


def influx_stat(host, test, profile, profile_path, stats, mult, latency_pps):
    points = []
    global_stats = stats['global']
    traffic_stats = stats['traffic']
    json_body = {
        "measurement": "trex_tests",
        "tags": {
            "host": host,
            "test_id": test,
            "profile": profile
        },
        "fields": {
        }
    }
    # Metrics description https://github.com/cisco-system-traffic-generator/trex-core/blob/master/scripts/automation/trex_control_plane/doc/api/json_fields.rst?plain=1#L135
    if latency_pps:
        json_body_lat = deepcopy(json_body)
        json_body_lat['measurement'] = 'trex_tests_latency'
        latency_stats = stats['latency']
        for port in latency_stats:
            json_body_lat['tags']['port'] = port
            port_stat_hist = latency_stats[port]['hist']['histogram']
            del latency_stats[port]['hist']['histogram']
            port_stat = flatten(latency_stats[port])
            for metric in port_stat:
                json_body_lat['fields']['latency_' + metric] = round(float(port_stat[metric]), 2)
            points.append(deepcopy(json_body_lat))
            json_body_lat['fields'] = {}
            total_pckts = sum(element['val'] for element in port_stat_hist)
            for hist_metric in port_stat_hist:
                json_body_lat['tags']['latency_usec'] = hist_metric['key']
                json_body_lat['fields']['pckt_prcnt'] = round(float((hist_metric['val'] / total_pckts) * 100), 2)
                points.append(deepcopy(json_body_lat))
                json_body_lat['fields'] = {}
    for k, v in global_stats.items():
        json_body['fields']['global_' + k] = round(float(v), 2)
    json_body['fields']['profile_name'] = profile
    json_body['fields']['profile_path'] = profile_path
    json_body['fields']['profile_mult_float'] = mult
    for direction in traffic_stats:
        for metric in MAIN_STATS:
            json_body['fields']['profile_' + direction + '_' + metric] = round(float(traffic_stats[direction][metric]), 2)
        for metric in DEBUG_STATS:
            json_body['fields']['profile_' + direction + '_' + metric] = round(float(traffic_stats[direction][metric]), 2)
    tcp_total_tx = traffic_stats['client'].get('tcps_sndtotal', 0) + traffic_stats['server'].get('tcps_sndtotal', 0)
    udp_total_tx = traffic_stats['client'].get('udps_sndpkt', 0) + traffic_stats['server'].get('udps_sndpkt', 0)
    tcp_total_tx_b = traffic_stats['client'].get('tcps_sndbyte', 0) + traffic_stats['server'].get('tcps_sndbyte', 0)
    tcp_total_rx_b = traffic_stats['client'].get('tcps_rcvbyte', 0) + traffic_stats['server'].get('tcps_rcvbyte', 0)
    udp_total_tx_b = traffic_stats['client'].get('udps_sndbyte', 0) + traffic_stats['server'].get('udps_sndbyte', 0)
    udp_total_rx_b = traffic_stats['client'].get('udps_rcvbyte', 0) + traffic_stats['server'].get('udps_rcvbyte', 0)
    tcp_drops_b = tcp_total_tx_b - tcp_total_rx_b
    udp_drops_b = udp_total_tx_b - udp_total_rx_b
    json_body['fields']['profile_total_tcp_tx'] = round(float(tcp_total_tx), 2)
    json_body['fields']['profile_total_udp_tx'] = round(float(udp_total_tx), 2)
    json_body['fields']['profile_total_tcp_tx_bytes'] = round(float(tcp_total_tx_b), 2)
    json_body['fields']['profile_total_udp_tx_bytes'] = round(float(udp_total_tx_b), 2)
    json_body['fields']['profile_total_tcp_drops_bytes'] = round(float(tcp_drops_b), 2)
    json_body['fields']['profile_total_udp_drops_bytes'] = round(float(udp_drops_b), 2)
    points.append(json_body)
    try:
        flux_client.write_points(points)
    except Exception as err:
        logging.info(err)
    return 0


def influxdb_send_annotation(host, test, description):
    json_body = {
        "measurement": "events",
        "fields": {
            "text": description,
            "test_id": test
        },
        "tags": {
            "host": host,
            "test_id": test,
        }
    }
    points = [json_body, ]
    try:
        flux_client.write_points(points)
    except Exception as err:
        logging.info(err)



def cyclic_stat(host, test, profile, profile_path, interval, mult, latency_pps, tunables, duration, cc_duration):
    skipped_kpi_start_period = float(tunables.get('ramp_up', 0)) if tunables else 0
    skipped_kpi_end_period = duration
    t_start = time.time()
    if cc_duration:
        skipped_kpi_start_period = duration
        skipped_kpi_end_period = duration + cc_duration
    while c.is_traffic_active():
        t_delta = time.time() - t_start
        stats = c.get_stats(skip_zero=False, pid_input=profile, is_sum=False)
        if skipped_kpi_start_period < t_delta < skipped_kpi_end_period:
            for kpi in KPI_GLOBAL:
                KPI_GLOBAL[kpi]['sum'] += stats['global'][kpi]
                KPI_GLOBAL[kpi]['count'] += 1
                KPI_GLOBAL[kpi]['avg'] = KPI_GLOBAL[kpi]['sum'] / KPI_GLOBAL[kpi]['count']
        influx_stat(host, test, profile, profile_path, stats, mult, latency_pps)
        time.sleep(interval)
    return 0


def get_all_files(directory):
    for dirpath, _, filenames in os.walk(directory):
        for f in sorted(filenames):
            yield os.path.abspath(os.path.join(dirpath, f))


def get_test_main_stat(stats, drops, error_timeout):
    main_stats = {
        'main_profile':
            {
                'client': {},
                'server': {},
                'global': {},
                'asserts': []
            }
    }
    for direction in stats['traffic']:
        if stats['traffic'][direction]['m_traffic_duration']:
            for metric in MAIN_STATS:
                if stats['traffic'][direction][metric]:
                    main_stats['main_profile'][direction][MAIN_STATS[metric]] = round(
                        stats['traffic'][direction][metric])
            avg_tx_pps = round(
                (stats['traffic'][direction]['udps_sndpkt'] + stats['traffic'][direction]['tcps_sndpack'])
                / stats['traffic'][direction]['m_traffic_duration'])
            avg_rx_pps = round(
                (stats['traffic'][direction]['udps_rcvpkt'] + stats['traffic'][direction]['tcps_rcvpack'])
                / stats['traffic'][direction]['m_traffic_duration'])
            main_stats['main_profile'][direction]['avg_tx_pps'] = avg_tx_pps
            main_stats['main_profile'][direction]['avg_rx_pps'] = avg_rx_pps
            #if not stats['traffic'][direction]['udps_keepdrops'] and not stats['traffic'][direction]['tcps_drops']:
            #    main_stats['main_profile'][direction]['tcp_udp_drops'] = 0
            #else:
            #    main_stats['main_profile'][direction]['tcp_udp_drops'] = stats['traffic'][direction]['udps_keepdrops'] \
            #                                                             + stats['traffic'][direction]['tcps_drops']
        else:
            main_stats['main_profile'][direction][MAIN_STATS['m_traffic_duration']] = 0
    client_stats = stats['traffic']['client']
    server_stats = stats['traffic']['server']
    tcp_total_tx_b = client_stats.get('tcps_sndbyte', 0) + server_stats.get('tcps_sndbyte', 0)
    udp_total_tx_b = client_stats.get('udps_sndbyte', 0) + server_stats.get('udps_sndbyte', 0)
    tcps_drops = client_stats.get('tcps_connattempt', 0) - server_stats.get('tcps_closed', 0) + server_stats.get('tcps_drops', 0) \
                 + server_stats.get('tcps_conndrops', 0) + server_stats.get('tcps_keepdrops', 0) + server_stats.get('tcps_timeoutdrop', 0) \
                 + server_stats.get('tcps_testdrops', 0)
    udps_drops = client_stats.get('udps_connects', 0) - server_stats.get('udps_closed', 0) + server_stats.get('udps_keepdrops', 0)
    conn_drp = round(float(((tcps_drops + udps_drops) / stats['global']['open_flows']) * 100), 4) if \
        stats['global']['open_flows'] else 0
    main_stats['main_profile']['global']['conn_drp_pct'] = conn_drp
    main_stats['main_profile']['error_timeout'] = error_timeout
    for kpi in KPI_GLOBAL:
        main_stats['main_profile']['global'][kpi] = int(KPI_GLOBAL[kpi]['avg'])
    if tcp_total_tx_b + udp_total_tx_b == 0:
        main_stats['main_profile']['asserts'].append('No any TCP or UDP sent App bytes')
    if conn_drp > drops:
        main_stats['main_profile']['asserts'].append('Too much drops (in connections): %s%%.'
                                                     ' Total conn drops: %s'
                                                     % (conn_drp, udps_drops + tcps_drops))
    return main_stats


def get_attack_stat(stats):
    attack_stats = {
        'attack_profiles':
            {
                'total_sent': 0,
                'blocked_ips': 0,
                'blocked_not_only_ips': 0,
                'allowed': 0,
                'skipped': 0,
                'allowed_list': [],
                'skipped_list': [],
                'asserts': []
            },
        'total_not_established_connections': 0
    }
    total_attacks = stats['total_blocked_ips'] + stats['total_blocked_not_only_ips'] + stats['total_allowed']
    attack_stats['attack_profiles']['total_sent'] = total_attacks
    attack_stats['attack_profiles']['blocked_ips'] = stats['total_blocked_ips']
    attack_stats['attack_profiles']['blocked_not_only_ips'] = stats['total_blocked_not_only_ips']
    attack_stats['attack_profiles']['allowed'] = stats['total_allowed']
    attack_stats['attack_profiles']['skipped'] = stats['total_skipped']
    if stats['total_allowed']:
        for attack in stats['allowed_set']:
            attack_stats['attack_profiles']['allowed_list'].append(attack)
    if stats['total_skipped']:
        for attack in stats['skipped_set']:
            attack_stats['attack_profiles']['skipped_list'].append(attack)
    if attack_stats['attack_profiles']['allowed'] > 0:
        attack_stats['attack_profiles']['asserts'].append('Found allowed attacks: %s.'
                                                          % (attack_stats['attack_profiles']['allowed']))
    attack_stats['total_not_established_connections'] = stats['total_not_established_conn']
    return attack_stats


def signal_handler(sig, frame):
    logging.warning('Abortion by user. Stop trex traffic.')
    c.reset()
    c.clear_stats()
    exit(0)


def start_traffic_capture(trex_client):
    # Start the capturing. Currently only on the client port.
    cap_meta = trex_client.start_capture(tx_ports=0, rx_ports=0)
    print(f'Start pcap capture: {cap_meta["id"]}')
    return cap_meta['id']


def stop_traffic_capture(cap_id, output):
    logging.info(f"Save captured packets to {output}")
    c.stop_capture(cap_id, output=output)


def astf_test(mult, duration, profile_path, attacks_path,
              drops, tunables, send_stats, test, influx_interval, latency_pps, cc_duration, attack_intv, pcap_cap,
              attacks_once):
    t_result = {'test_id': test}
    logging.info('Start test {}'.format(test))
    timeout_duration = DEFAULT_TIMEOUT_SEC
    if duration < 0:
        timeout_duration = 0
    if cc_duration > 0:
        timeout_duration = timeout_duration + duration + cc_duration
    error_timeout = False
    # load main ASTF profile if it exists
    if profile_path:
        profile_name = os.path.basename(profile_path)
        try:
            if tunables:
                profile = ASTFProfile.load(profile_path, **tunables)
                c.load_profile(profile, pid_input=MAIN_PROFILE_ID)
                # print(json.dumps(profile.print_stats(), indent=2))
                if 'ramp_up' in tunables and duration > 0:
                    duration = duration + float(tunables['ramp_up'])
            else:
                profile = ASTFProfile.load(profile_path)
                c.load_profile(profile, pid_input=MAIN_PROFILE_ID)
        except TRexError as e:
            logging.error(e)
            exit(1)
        try_num = 1
        while not c.get_profiles_state().get(MAIN_PROFILE_ID):
            if try_num > RETRY:
                logging.error("Profile {} wasn't loaded. Exit.".format(MAIN_PROFILE_ID))
                exit(1)
            logging.info('Wait on profile load (%s/%s)...' % (try_num, RETRY))
            try_num += 1
            time.sleep(0.2)
        if pcap_cap:
            cap_id = start_traffic_capture(c)
        try:
            c.start(t_duration=timeout_duration, pid_input=MAIN_PROFILE_ID, mult=mult, duration=duration,
                    latency_pps=latency_pps)
        except TRexError as e:
            t_result['error'] = str(e)
            print(json.dumps(t_result, indent=2))
            logging.info(f'Stop the test: {e}')
            exit(1)
        logging.info("Start main profile %s with %s multiplier for %s seconds" % (profile_path, mult, duration))
        if send_stats:
            thread_stat = threading.Thread(target=cyclic_stat,
                                           args=(trex_host, test, MAIN_PROFILE_ID, profile_path, influx_interval, mult,
                                                 latency_pps, tunables, duration, cc_duration))
            thread_stat.start()
    # load attack profiles if it exists
    if attacks_path:
        system_info = c.get_server_system_info()
        dp_cores_num = system_info['dp_core_count']
        attacks_all = get_all_files(attacks_path)
        attacks_pool = cycle(attacks_all)
        attack_index = 1
        if attacks_once: stop_time = 0
        elif duration > 0: stop_time = time.time() + duration
        else: stop_time = float("inf")
        attack_stats = {'total_blocked_ips': 0,
                        'total_blocked_not_only_ips': 0,
                        'total_allowed': 0,
                        'total_skipped': 0,
                        'total_not_established_conn': 0,
                        'allowed_set': set(),
                        'skipped_set': set()
                        }
        remaining_attacks = len(list(get_all_files(attacks_path))) if attacks_once else 0
        while time.time() < stop_time or remaining_attacks > 0:
            absolute_pcap_path = next(attacks_pool)
            _, relative_pcap_path = os.path.split(absolute_pcap_path)
            if relative_pcap_path in attack_stats['skipped_set']:
                remaining_attacks -= 1
                continue
            logging.info("Send attack {0} using pcap {1}".format(attack_index, relative_pcap_path))
            c.load_profile(SINGLE_ATTACK_PROFILE, pid_input=ATTACK_PROFILE_ID.format(attack_index),
                           tunables={"pcap": absolute_pcap_path, "dp_cores": dp_cores_num})
            try:
                c.start(t_duration=timeout_duration, pid_input=ATTACK_PROFILE_ID.format(attack_index), mult=1.0,
                        duration=1)
            except TRexError as e:
                dport = re.findall('port (\d+)', str(e))[0]
                logging.info('Skip attack {0}: the same DST '
                             'port as for the main profile ({1}).'.format(attack_index, dport))
                attack_stats['total_skipped'] += 1
                attack_stats['skipped_set'].add(relative_pcap_path)
                c.stop(block=False, pid_input=ATTACK_PROFILE_ID.format(attack_index), is_remove=True)
                while c.get_profiles_state().get(ATTACK_PROFILE_ID.format(attack_index)):
                    time.sleep(0.001)
                time.sleep(attack_intv)
                remaining_attacks -= 1
                continue
            else:
                c.wait_on_traffic(profile_id=ATTACK_PROFILE_ID.format(attack_index))
                stats = c.get_stats(skip_zero=False, pid_input=ATTACK_PROFILE_ID.format(attack_index), is_sum=False)
                not_established_conn = stats['traffic']['client']['tcps_connattempt']\
                                       + stats['traffic']['client']['udps_connects']\
                                       - stats['traffic']['server']['tcps_closed']\
                                       - stats['traffic']['server']['udps_closed']
                conn_drops = stats['traffic']['server']['tcps_drops'] + stats['traffic']['server']['udps_keepdrops']
                conn_closed = stats['traffic']['server']['tcps_closed'] + stats['traffic']['server']['udps_closed']

                conn_allowed = conn_closed - conn_drops
                if not conn_allowed and not_established_conn:
                    logging.info(f"Attack {attack_index} was blocked not only by IPS. "
                                 f"Blocked connections by IPS: {conn_drops}. "
                                 f"Not established connections: {not_established_conn}")
                    attack_stats['total_blocked_not_only_ips'] += 1
                elif not conn_allowed and not not_established_conn:
                    logging.info(f"Attack {attack_index} was blocked by IPS. Blocked connections by IPS: {conn_drops}.")
                    attack_stats['total_blocked_ips'] += 1
                else:
                    logging.info(f"Attack {attack_index} was allowed. Allowed connections by IPS: {conn_allowed}. "
                                 f"Blocked connections by IPS: {conn_drops}. "
                                 f"Not established connections: {not_established_conn}")
                    attack_stats['total_allowed'] += 1
                    attack_stats['allowed_set'].add(relative_pcap_path)
                attack_stats['total_not_established_conn'] += not_established_conn
                if send_stats:
                    stats['global']['attack_allowed'] = bool(conn_allowed)
                    influx_stat(trex_host, test, ATTACK_PROFILE_ID.format(attack_index), relative_pcap_path, stats,
                                mult=1.0, latency_pps=0)
                c.clear_profile(pid_input=ATTACK_PROFILE_ID.format(attack_index), block=False)
                while c.get_profiles_state().get(ATTACK_PROFILE_ID.format(attack_index)):
                    time.sleep(0.001)
                attack_index += 1
                remaining_attacks -= 1
                time.sleep(attack_intv)
    if profile_path:
        if attacks_once:
            c.stop(pid_input=MAIN_PROFILE_ID)
            logging.info(f'Waiting timeout {DEFAULT_TIMEOUT_SEC} seconds for closing connections.')
            time.sleep(DEFAULT_TIMEOUT_SEC)
        else:
            try:
                if timeout_duration:
                    c.wait_on_traffic(timeout=duration + timeout_duration, profile_id=MAIN_PROFILE_ID)
                else:
                    c.wait_on_traffic(profile_id=MAIN_PROFILE_ID)
            except TRexTimeoutError as e:
                logging.info(e)
                c.stop(pid_input=MAIN_PROFILE_ID)
                error_timeout = True
        if send_stats: thread_stat.join()
        logging.info("Stop main profile.")
        if pcap_cap:
            output_f = tunables['pattern'].replace('.yaml', '.pcap') if tunables.get('pattern', None) else \
                os.path.join(SCRIPT_ROOT_PATH, test + '_' + time.strftime("%Y-%m-%dT%H-%M-%S") + '.pcap')
            stop_traffic_capture(cap_id, output_f)
        main_stats = c.get_stats(skip_zero=False, pid_input=MAIN_PROFILE_ID, is_sum=False)
        if send_stats:
            influx_stat(trex_host, test, MAIN_PROFILE_ID, profile_path, main_stats, mult, latency_pps)
        test_main_stats = get_test_main_stat(main_stats, drops, error_timeout)
        t_result.update(test_main_stats)
    if attacks_path:
        test_attack_stats = get_attack_stat(attack_stats)
        t_result.update(test_attack_stats)
    t_result['result'] = 'Failed' if t_result.get('main_profile', {}).get('asserts', {}) or \
                                     t_result.get('attack_profiles', {}).get('asserts', {}) else 'Passed'
    c.disconnect()

    return t_result


def parse_args():
    parser = argparse.ArgumentParser(description='TRex ASTF mode',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-s',
                        dest='server',
                        help='remote TRex address',
                        default='127.0.0.1',
                        type=str)
    parser.add_argument('--sync_port',
                        dest='sync_port',
                        help='the RPC port',
                        default='4501',
                        type=int)
    parser.add_argument('--async_port',
                        dest='async_port',
                        help='the ASYNC port (subscriber port)',
                        default='4500',
                        type=int)
    parser.add_argument('--trex_instance',
                        dest='trex_instance',
                        help='Trex instance',
                        default=None)
    parser.add_argument('-m',
                        dest='mult',
                        help='multiplier of main traffic',
                        default=1.0,
                        type=float)
    parser.add_argument('-f',
                        dest='file',
                        help='profile path for sending main traffic',
                        type=str)
    parser.add_argument('-d',
                        default=10,
                        dest='duration',
                        help='duration of traffic, sec',
                        type=float)
    parser.add_argument('-a',
                        dest='attacks_path',
                        help='attack pcaps absolute path directory for sending attacks',
                        type=str)
    parser.add_argument('--drp',
                        default=0.1,
                        dest='drp',
                        help='Allowed main traffic drops (connections), %%',
                        type=float)
    parser.add_argument('-t',
                        dest='tunables',
                        help='tunables for main profile: key1=value1 key2=value2...',
                        nargs='*',
                        action=Keyvalue,
                        default={})
    parser.add_argument('--send_stats',
                        default=False,
                        dest='send_stats',
                        help='Send stats to InfluxDB',
                        type=util.strtobool)
    parser.add_argument('--influx_addr',
                        dest='influx_addr',
                        help='InfluxDB address',
                        default='127.0.0.1',
                        type=str)
    parser.add_argument('--influx_port',
                        dest='influx_port',
                        help='InfluxDB port',
                        default=8086,
                        type=int)
    parser.add_argument('--influx_admin',
                        dest='influx_admin',
                        help='InfluxDB admin user',
                        default='admin',
                        type=str)
    parser.add_argument('--influx_passwd',
                        dest='influx_passwd',
                        help='InfluxDB admin password',
                        default='admin',
                        type=str)
    parser.add_argument('--influx_db',
                        dest='influx_db',
                        help='Influx DB name',
                        default='trex',
                        type=str)
    parser.add_argument('--influx_interval',
                        dest='influx_interval',
                        help='Influx send interval, sec',
                        default=10,
                        type=int)
    parser.add_argument('--grafana_url',
                        dest='grafana_url',
                        help='Grafana URL',
                        default='http://127.0.0.1:3000',
                        type=str)
    parser.add_argument('--latency_pps',
                        dest='latency_pps',
                        help='ICMP packets rate',
                        default=0,
                        type=int)
    parser.add_argument('--json',
                        dest='json_out',
                        help='Output in json format',
                        action="store_true",
                        default=False)
    parser.add_argument('--bw',
                        dest='get_bw',
                        help='Get resolved ports bandwidth',
                        action="store_true",
                        default=False)
    parser.add_argument('--ngfw-hostname',
                        dest='ngfw_host',
                        help='NGFW hostname for grafana dashboards',
                        default=None)
    parser.add_argument('--cc-dur',
                        dest='cc_duration',
                        help='Concurrent connections steady state duration, sec',
                        type=float,
                        default=0)
    parser.add_argument('--attack-interval',
                        dest='attack_interval',
                        help='Time interval between attacks sending, sec',
                        type=float,
                        default=1.0)
    parser.add_argument('--capture',
                        dest='pcap_cap',
                        help='Capture first 1000 pckts since starting main profile',
                        action="store_true",
                        default=False)
    parser.add_argument('--attacks-once',
                        dest='attacks_once',
                        help='Send all attacks only once',
                        action="store_true",
                        default=False)
    parser.add_argument('--arp-retries',
                        dest='arp_retries',
                        help='ARP retries with 1 second interval',
                        default=10,
                        type=int)
    return parser.parse_args()


signal.signal(signal.SIGINT, signal_handler)
args = parse_args()
log_level = 'WARN' if args.json_out else 'INFO'
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
                    encoding='utf-8', level=log_level,
                    handlers=[logging.StreamHandler()])
if not args.file and not args.attacks_path:
    logging.error('Error: at least main profile or attacks path should be exist.')
    exit(1)
if args.send_stats:
    try:
        flux_client = InfluxDBClient(args.influx_addr, args.influx_port, args.influx_admin, args.influx_passwd,
                                     args.influx_db)
        flux_client.ping()
    except Exception as err:
        logging.error("InfluxDB Error: {0}.".format(err))
        exit(1)
if not args.trex_instance:
    args.trex_instance = 'trex1'
args.trex_ngfw = args.trex_instance + '-' + args.ngfw_host if args.ngfw_host else args.trex_instance
try:
    c = ASTFClient(server=args.server, sync_port=args.sync_port, async_port=args.async_port)
    c.connect()
    c.reset()
    c.clear_stats()
    used_ports = c.get_acquired_ports()
    # Check if trex was configured with L2 or L3 mode
    if c.get_resolvable_ports():
        c.set_service_mode(ports=used_ports, enabled=True)
        for i in range(args.arp_retries):
            try:
                logging.info('Trying to resolve DUT ports...')
                c.arp(ports=used_ports)
                break
            except TRexError as e:
                if i < args.arp_retries - 1:
                    time.sleep(1)
                else:
                    raise Exception(f"{e}")
        c.set_service_mode(ports=used_ports, enabled=False)
except TRexError as e:
    logging.error(e)
    c.set_service_mode(ports=used_ports, enabled=False)
    c.disconnect()
    exit(0)
if args.get_bw:
    ports_speed = []
    for port_id in used_ports:
        port_speed = c.get_port_attr(port_id)['speed']
        ports_speed.append(port_speed)
    result_port_speed = min(ports_speed)
    print(int(result_port_speed))
    exit(0)

trex_host = socket.gethostname()
start_time = int(time.time()) * 1000
if args.attacks_once:
    logging.warning(f'With key --attacks-once parameter -d will be ignored.')
    args.duration = -1

if args.send_stats:
    influxdb_send_annotation(trex_host, test=args.trex_ngfw, description="Start")
test_result = astf_test(mult=args.mult, duration=args.duration, profile_path=args.file,
                        attacks_path=args.attacks_path, drops=args.drp, tunables=args.tunables,
                        send_stats=args.send_stats, test=args.trex_ngfw, influx_interval=args.influx_interval,
                        latency_pps=args.latency_pps, cc_duration=args.cc_duration, attack_intv=args.attack_interval,
                        pcap_cap=args.pcap_cap, attacks_once=args.attacks_once)

if args.send_stats:
    influxdb_send_annotation(trex_host, test=args.trex_ngfw, description="Stop")
    end_time = int(time.time()) * 1000
    test_result['grafana_urls'] = grafana_url(args.grafana_url, start_time, end_time, trex_host, args.trex_ngfw,
                                              args.ngfw_host)
print(json.dumps(test_result, indent=2))
