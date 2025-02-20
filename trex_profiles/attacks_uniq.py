from trex.astf.api import *
import argparse
import os
import re

class Prof1():
    def __init__(self):
        pass

    def get_all_files(self, directory):
        for dirpath,_,filenames in os.walk(directory):
            for f in filenames:
                yield os.path.abspath(os.path.join(dirpath, f))

    def create_profile(self, pcaps):
        # ip generator
        pcaps_list = self.get_all_files(pcaps)
        all_cap_info = []
        unique_dst_ports = []
        for pcap in pcaps_list:
            dst_port = re.findall('dst_port_(\d+)', pcap)[0]
            if dst_port:
                if dst_port not in unique_dst_ports:
                    print(pcap)
                    all_cap_info.append(ASTFCapInfo(file=pcap, cps=0.5))
                    unique_dst_ports.append(dst_port)
        ip_gen_c = ASTFIPGenDist(ip_range=["10.0.255.200", "10.0.255.250"], distribution="rand")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.1.255.200", "48.1.255.250"], distribution="rand")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        profile = ASTFProfile(default_ip_gen=ip_gen, cap_list=all_cap_info)

        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--pcaps',
                            type=str,
                            required=True,
                            help='pcaps absolute path')

        args, unknown = parser.parse_known_args(tunables)
        if unknown:
            raise Exception('unrecognized arguments {0}\n{1}'.format(unknown, parser.format_usage()))
        pcaps = args.pcaps
        return self.create_profile(pcaps)


def register():
    return Prof1()
