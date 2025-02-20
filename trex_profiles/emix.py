from trex.astf.api import *
import argparse



class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, ramp_up):
        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["10.0.0.1", "10.0.255.199"], distribution="rand")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.1", "48.1.255.199"], distribution="rand")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)
       # Set rx/tx buffer to 64K. TCP window size also will be 64K
        c_glob_info = ASTFGlobalInfo()
        c_glob_info.tcp.rxbufsize = 65535
        c_glob_info.tcp.txbufsize = 65535
        if ramp_up: c_glob_info.scheduler.rampup_sec = ramp_up

        s_glob_info = ASTFGlobalInfo()
        s_glob_info.tcp.rxbufsize = 65535
        s_glob_info.tcp.txbufsize = 65535

        profile = ASTFProfile(default_ip_gen=ip_gen,
                              default_c_glob_info=c_glob_info, 
                              default_s_glob_info=s_glob_info,
                              cap_list=[
            #TLS
            ASTFCapInfo(file="../trex-pcaps/https-tls1.2-nginx-trex-256kb.pcap", cps=3, port=443),
            #NFS
            ASTFCapInfo(file="../trex-pcaps/NFS.CB-NFS-RPC-TCP-dst-port-2049-pkts-61.pcap", cps=5),
            #HTTP
            ASTFCapInfo(file="../trex-pcaps/DATA-HTTP-TCP-dst-port-80-pkts-34.pcap", cps=2),
            #SMB
            ASTFCapInfo(file="../trex-pcaps/SMB-TCP-dst-port-139-pkts-36.pcap", cps=2),
            #DNS
            ASTFCapInfo(file="../trex-pcaps/DNS-UDP-dst-port-53-pkts-39.pcap", cps=1.5),
            #SMTP
            ASTFCapInfo(file="../trex-pcaps/SMTP-TCP-dst-port-25-pkts-36.pcap", cps=1),
            #POP3
            ASTFCapInfo(file="../trex-pcaps/POP-IMF-TCP-dst-port-110-pkts-72.pcap", cps=0.5),
            #Imap
            ASTFCapInfo(file="../trex-pcaps/IMAP-TCP-dst-port-143-pkts-62.pcap", cps=2),
            #SIP
            ASTFCapInfo(file="../trex-pcaps/SIP-UDP-dst-port-5060-pkts-27.pcap", cps=1),
            #RDP
            ASTFCapInfo(file="../trex-pcaps/RDPUDP-UDP-dst-port-3389-pkts-9.pcap", cps=5),
            #SYSLOG
            ASTFCapInfo(file="../trex-pcaps/SYSLOG-UDP-dst-port-514-pkts-58.pcap", cps=1),
            #SYSLOG
            ASTFCapInfo(file="../trex-pcaps/SSH-TCP-dst-port-22-pkts-47.pcap", cps=1)
        ])

        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--ramp_up',
                            type=int,
                            default=0,
                            help='Ramp up period (sec)')
        args, unknown = parser.parse_known_args(tunables)
        if unknown:
            raise Exception('unrecognized arguments {0}\n{1}'.format(unknown, parser.format_usage()))
        return self.create_profile(args.ramp_up)


def register():
    return Prof1()
