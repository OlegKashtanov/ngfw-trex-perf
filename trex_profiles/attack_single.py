from trex.astf.api import *
import argparse


class Prof1():
    def __init__(self):
        pass

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        parser.add_argument('--pcap',
                            type=str,
                            help='pcap path')
        args, unknown = parser.parse_known_args(tunables)
        if unknown:
            raise Exception('unrecognized arguments {0}\n{1}'.format(unknown, parser.format_usage()))
        pcap = args.pcap
        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["10.0.255.200", "10.0.255.250"], distribution="rand")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.255.200", "48.0.255.250"], distribution="rand")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        return ASTFProfile(default_ip_gen=ip_gen,
                            cap_list=[ASTFCapInfo(file=pcap,
                            cps=0.5)])


def register():
    return Prof1()

