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

from copy import deepcopy
from datetime import datetime
from itertools import cycle
from trex.astf.api import *
from influxdb import InfluxDBClient
from distutils import util
from flatten_json import flatten

curr_dir = os.path.dirname(os.path.abspath(__file__))
SINGLE_ATTACK_PROFILE = os.path.join(curr_dir, 'trex_profiles', 'attack_single.py')
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
]
# retry counts to start trex
_RETRY = 5


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


def grafana_url(host, dashboard_uid, dashboard, from_time, to_time, trex, test_id):
    time_offset = 10_000  # 10 Seconds time offset
    grafana_url_sample = "{0}/d/{1}/{2}?var-host={3}&var-test_id={4}&from={5}&to={6}"
    url = grafana_url_sample.format(host, dashboard_uid, dashboard, trex, test_id,
                                    from_time - time_offset, to_time + time_offset)
    return url


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
    json_body['fields']['profile_mult'] = mult
    for direction in traffic_stats:
        for metric in MAIN_STATS:
            json_body['fields']['profile_' + direction + '_' + metric] = round(float(traffic_stats[direction][metric]),
                                                                               2)
        for metric in DEBUG_STATS:
            json_body['fields']['profile_' + direction + '_' + metric] = round(float(traffic_stats[direction][metric]),
                                                                               2)
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
    flux_client.write_points(points)
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
    flux_client.write_points(points)


def cyclic_influx_stat(host, test, profile, profile_path, interval, mult, latency_pps):
    while c.is_traffic_active():
        stats = c.get_stats(skip_zero=False, pid_input=profile, is_sum=False)
        influx_stat(host, test, profile, profile_path, stats, mult, latency_pps)
        time.sleep(interval)
    return 0


def get_all_files(directory):
    for dirpath, _, filenames in os.walk(directory):
        for f in filenames:
            yield os.path.abspath(os.path.join(dirpath, f))


def print_date(msg):
    print(datetime.now().strftime("%Y-%m-%dT%H:%M:%S") + " " + msg)


def print_main_stat(stats):
    print('\n\nMain profile summary stats:')
    for direction in stats['traffic']:
        if stats['traffic'][direction]['m_traffic_duration']:
            print(' - {} stats:'.format(direction))
            for metric in MAIN_STATS:
                if stats['traffic'][direction][metric]:
                    print('\t{0}: {1}'.format(MAIN_STATS[metric], round(stats['traffic'][direction][metric])))
            avg_tx_pps = round(
                (stats['traffic'][direction]['udps_sndpkt'] + stats['traffic'][direction]['tcps_sndpack'])
                / stats['traffic'][direction]['m_traffic_duration'])
            avg_rx_pps = round(
                (stats['traffic'][direction]['udps_rcvpkt'] + stats['traffic'][direction]['tcps_rcvpack'])
                / stats['traffic'][direction]['m_traffic_duration'])
            print('\tAvg TX PPS: {}'.format(avg_tx_pps))
            print('\tAvg RX PPS: {}'.format(avg_rx_pps))
            if not stats['traffic'][direction]['udps_keepdrops'] and not stats['traffic'][direction]['tcps_drops']:
                print('\tNo session drops')
        else:
            print('{}: 0'.format(MAIN_STATS['m_traffic_duration']))
    return 0


def print_attack_stat(stats):
    total_attacks = stats['total_blocked'] + stats['total_allowed']
    print("\n\nAttacks summary stats:")
    print("Total sent attacks: {0}".format(total_attacks))
    print("\t - blocked attacks: {0}".format(stats['total_blocked']))
    print("\t - allowed attacks: {0}".format(stats['total_allowed']))
    if stats['total_allowed']:
        print("Pcaps list of allowed attacks:")
        for attack in stats['allowed_set']:
            print('\t - ' + attack)
    print("Total skipped attacks: {0}".format(stats['total_skipped']))
    if stats['total_skipped']:
        print("Pcaps list of skipped attacks:")
        for attack in stats['skipped_set']:
            print('\t - ' + attack)
    return 0


def main_stats_evaluation(main_stats, drops):
    try:
        print('Main profile results evaluation:')
        client_stats = main_stats['traffic']['client']
        server_stats = main_stats['traffic']['server']
        tcp_total_tx_b = client_stats.get('tcps_sndbyte', 0) + server_stats.get('tcps_sndbyte', 0)
        tcp_total_rx_b = client_stats.get('tcps_rcvbyte', 0) + server_stats.get('tcps_rcvbyte', 0)
        udp_total_tx_b = client_stats.get('udps_sndbyte', 0) + server_stats.get('udps_sndbyte', 0)
        udp_total_rx_b = client_stats.get('udps_rcvbyte', 0) + server_stats.get('udps_rcvbyte', 0)
        tcp_drp = round(((tcp_total_tx_b - tcp_total_rx_b) / tcp_total_tx_b) * 100) if tcp_total_tx_b else 0
        udp_drp = round(((udp_total_tx_b - udp_total_rx_b) / udp_total_tx_b) * 100) if udp_total_tx_b else 0
        assert (tcp_total_tx_b + udp_total_tx_b > 0), '[Failed] No any TCP or UDP sent App bytes'
        assert (tcp_drp <= drops), '\t - [Failed] Too much TCP drops (in bytes): %s%%. ' \
                                   'Total TX: %s bytes, Total RX: %s bytes' % (tcp_drp, tcp_total_tx_b, tcp_total_rx_b)
        assert (udp_drp <= drops), '\t - [Failed] Too much UDP drops (in bytes): %s%%. ' \
                                   'Total TX: %s bytes, Total RX: %s bytes' % (udp_drp, udp_total_tx_b, udp_total_rx_b)
    except AssertionError as e:
        print(e)
        return 1
    else:
        print('\tNo issues.')
        return 0


def attacks_stats_evaluation(attack_stats):
    try:
        print('Attacks results evaluation:')
        allowed_attacks = attack_stats['total_allowed']
        assert (allowed_attacks == 0), '\t - [Failed] Found allowed attacks: %s\n' % allowed_attacks
    except AssertionError as e:
        print(e)
        return 1
    else:
        print('\tNo issues.')
        return 0


def signal_handler(sig, frame):
    print('Abortion by user. Stop trex traffic.')
    c.reset()
    c.clear_stats()
    sys.exit(0)


def astf_test(mult, duration, profile_path, attacks_path,
              drops, tunables, send_stats, influx_interval, test, latency_pps):
    errors = 0
    print_date('Start test {}'.format(test))
    # load main ASTF profile if it exists
    if profile_path:
        try:
            c.load_profile(profile_path, pid_input=MAIN_PROFILE_ID, tunables=tunables) if tunables \
                else c.load_profile(profile_path, pid_input=MAIN_PROFILE_ID)
        except TRexError as e:
            print(e)
            sys.exit(1)
        try_num = 1
        while not c.get_profiles_state().get(MAIN_PROFILE_ID):
            if try_num > _RETRY:
                print("Profile {} wasn't loaded. Exit.".format(MAIN_PROFILE_ID))
                sys.exit(1)
            print('Wait on profile load (%s/%s)...' % (try_num, _RETRY))
            try_num += 1
            time.sleep(0.2)

        c.start(nc=True, pid_input=MAIN_PROFILE_ID, mult=mult, duration=duration, latency_pps=latency_pps)
        print_date("Start main profile %s with %s multiplier for %s seconds" % (profile_path, mult, duration))
        if send_stats:
            thread = threading.Thread(target=cyclic_influx_stat,
                                      args=(trex_host, test, MAIN_PROFILE_ID, profile_path, influx_interval, mult,
                                            latency_pps))
            thread.start()
    # load attack profiles if it exists
    if attacks_path:
        attacks_all = get_all_files(attacks_path)
        attacks_pool = cycle(attacks_all)
        attack_index = 1
        stop_time = time.time() + duration
        attack_stats = {'total_blocked': 0,
                        'total_allowed': 0,
                        'total_skipped': 0,
                        'allowed_set': set(),
                        'skipped_set': set()
                        }
        while time.time() < stop_time:
            absolute_pcap_path = next(attacks_pool)
            relative_pcap_path = absolute_pcap_path.replace(attacks_path, '')
            if relative_pcap_path in attack_stats['skipped_set']:
                continue
            print_date("Send attack {0} using pcap {1}".format(attack_index, relative_pcap_path))
            c.load_profile(SINGLE_ATTACK_PROFILE, pid_input=ATTACK_PROFILE_ID.format(attack_index),
                           tunables={"pcap": absolute_pcap_path})
            try:
                c.start(pid_input=ATTACK_PROFILE_ID.format(attack_index), mult=1, duration=1)
            except TRexError as e:
                dport = re.findall('port (\d+)', str(e))[0]
                print_date('[WARN] Skip attack {0}: the same DST '
                           'port as for the main profile ({1}).'.format(attack_index, dport))
                attack_stats['total_skipped'] += 1
                attack_stats['skipped_set'].add(relative_pcap_path)
                c.stop(block=False, pid_input=ATTACK_PROFILE_ID.format(attack_index), is_remove=True)
                while c.get_profiles_state().get(ATTACK_PROFILE_ID.format(attack_index)):
                    time.sleep(0.001)
                continue
            else:
                c.wait_on_traffic(profile_id=ATTACK_PROFILE_ID.format(attack_index))
                stats = c.get_stats(skip_zero=False, pid_input=ATTACK_PROFILE_ID.format(attack_index), is_sum=False)
                conn_drops = stats['traffic']['client']['tcps_drops'] + stats['traffic']['client']['udps_keepdrops']
                conn_closed = stats['traffic']['client']['tcps_closed'] + stats['traffic']['client']['udps_closed']
                conn_allowed = conn_closed - conn_drops
                if not conn_allowed:
                    print_date("Attack {0} was blocked. "
                               "Blocked connections: {1}".format(attack_index, conn_drops))
                    attack_stats['total_blocked'] += 1
                else:
                    print_date("Attack {0} was allowed. Allowed connections: {1}. "
                               "Blocked connections: {2}".format(attack_index, conn_allowed, conn_drops))
                    attack_stats['total_allowed'] += 1
                    attack_stats['allowed_set'].add(relative_pcap_path)
                if send_stats:
                    stats['global']['attack_allowed'] = bool(conn_allowed)
                    influx_stat(trex_host, test, ATTACK_PROFILE_ID.format(attack_index), relative_pcap_path, stats,
                                mult=1, latency_pps=0)
                c.clear_profile(pid_input=ATTACK_PROFILE_ID.format(attack_index), block=False)
                while c.get_profiles_state().get(ATTACK_PROFILE_ID.format(attack_index)):
                    time.sleep(0.001)
                attack_index += 1
                time.sleep(1)

    if profile_path:
        c.wait_on_traffic(profile_id=MAIN_PROFILE_ID)
        if send_stats: thread.join()
        print_date("Stop main profile.")
        main_stats = c.get_stats(skip_zero=False, pid_input=MAIN_PROFILE_ID, is_sum=False)
        print_main_stat(main_stats)
        errors += main_stats_evaluation(main_stats=main_stats, drops=drops)
        # print(json.dumps(main_stats, indent=2))
    if attacks_path:
        print_attack_stat(attack_stats)
        errors += attacks_stats_evaluation(attack_stats=attack_stats)

    c.disconnect()

    return errors


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
    parser.add_argument('-m',
                        dest='mult',
                        help='multiplier of main traffic',
                        default=1,
                        type=int)
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
                        default=1,
                        dest='drp',
                        help='Allowed main traffic drop rate, %%',
                        type=int)
    parser.add_argument('-t',
                        dest='tunables',
                        help='tunables for main profile: key1=value1 key2=value2...',
                        nargs='*',
                        action=Keyvalue)
    parser.add_argument('--send_stats',
                        default=True,
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
    parser.add_argument('--test_id',
                        dest='test_id',
                        help='Test ID',
                        default=None,
                        type=str)
    parser.add_argument('--grafana_url',
                        dest='grafana_url',
                        help='Grafana URL',
                        default='http://127.0.0.1:3000',
                        type=str)
    parser.add_argument('--dashboard_uid',
                        dest='dashboard_uid',
                        help='Dashboard UID',
                        default='cisco-trex',
                        type=str)
    parser.add_argument('--dashboard_name',
                        dest='dashboard_name',
                        help='Dashboard name',
                        default='cisco-trex',
                        type=str)
    parser.add_argument('--latency_pps',
                        dest='latency_pps',
                        help='ICMP packets rate',
                        default=0,
                        type=int)
    return parser.parse_args()


signal.signal(signal.SIGINT, signal_handler)
args = parse_args()
if not args.file and not args.attacks_path:
    print('Error: at least main profile or attacks path should be exist.')
    exit(1)
if args.send_stats:
    try:
        flux_client = InfluxDBClient(args.influx_addr, args.influx_port, args.influx_admin, args.influx_passwd,
                                     args.influx_db)
        flux_client.ping()
    except Exception as err:
        print("InfluxDB Error: {0}.".format(err))
        exit(1)
if not args.test_id:
    args.test_id = 'test_' + time.strftime("%Y-%m-%dT%H:%M:%S")

c = ASTFClient(server=args.server, sync_port=args.sync_port, async_port=args.async_port)
c.connect()
c.reset()
c.clear_stats()
trex_host = socket.gethostname()
start_time = int(time.time()) * 1000
if args.send_stats:
    influxdb_send_annotation(trex_host, test=args.test_id, description="Start")
result_errors = astf_test(mult=args.mult, duration=args.duration, profile_path=args.file,
                          attacks_path=args.attacks_path, drops=args.drp, tunables=args.tunables,
                          send_stats=args.send_stats, test=args.test_id, influx_interval=args.influx_interval,
                          latency_pps=args.latency_pps)

if args.send_stats:
    influxdb_send_annotation(trex_host, test=args.test_id, description="Stop")
    end_time = int(time.time()) * 1000
    print("Grafana test URL: {}".format(grafana_url(args.grafana_url,
                                                    args.dashboard_uid, args.dashboard_name,
                                                    start_time, end_time, trex_host, args.test_id)))

if not result_errors:
    print('\nTest {} has passed.\n'.format(args.test_id))
else:
    print('\nTest {} has failed.\n'.format(args.test_id))
    sys.exit(1)
