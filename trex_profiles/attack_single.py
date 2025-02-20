from trex.astf.api import *
import argparse
import random
import ipaddress

class Prof1():
    def __init__(self):
        self.p1_src_start_ip = '10.0.255.200'
        self.p1_src_end_ip = '10.0.255.250'

        self.p1_dst_start_ip = '48.1.255.200'
        self.p1_dst_end_ip = '48.1.255.250'

    def random_ip_range(self, start_ip, end_ip, dp_cores_num):
        start_int = int(ipaddress.IPv4Address(start_ip))
        end_int = int(ipaddress.IPv4Address(end_ip))
        if end_int - start_int + 1 < dp_cores_num:
            raise Exception("The number of DP cores is larger than given IP range.")
        max_start = end_int - dp_cores_num + 1
        start_range_int = random.randint(start_int, max_start)
        start_rand_ip = str(ipaddress.IPv4Address(start_range_int))
        end_rand_ip = str(ipaddress.IPv4Address(start_range_int + dp_cores_num))
        return start_rand_ip, end_rand_ip


    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        parser.add_argument('--pcap',
                            type=str,
                            help='pcap path')
        parser.add_argument('--dp_cores',
                            type=int,
                            help='DP cores number')
        args, unknown = parser.parse_known_args(tunables)
        if unknown:
            raise Exception('unrecognized arguments {0}\n{1}'.format(unknown, parser.format_usage()))
        pcap = args.pcap
        dp_cores = args.dp_cores
        # ip generator
        rand_src_start_ip, rand_src_end_ip = self.random_ip_range(self.p1_src_start_ip, self.p1_src_end_ip, dp_cores)
        rand_dst_start_ip, rand_dst_end_ip = self.random_ip_range(self.p1_dst_start_ip, self.p1_dst_end_ip, dp_cores)
        ip_gen_c = ASTFIPGenDist(ip_range=[rand_src_start_ip, rand_src_end_ip], distribution="rand")
        ip_gen_s = ASTFIPGenDist(ip_range=[rand_dst_start_ip, rand_dst_end_ip], distribution="rand")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        return ASTFProfile(default_ip_gen=ip_gen,
                            cap_list=[ASTFCapInfo(file=pcap,
                            cps=0.5, limit=1)])


def register():
    return Prof1()

