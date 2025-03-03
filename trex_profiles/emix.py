from trex.astf.api import *
import argparse



class Prof1():
    def init(self):
        pass  # tunables

    def create_profile(self):
        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["10.0.0.1", "10.0.255.199"], distribution="rand")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.1", "48.1.255.199"], distribution="rand")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        profile = ASTFProfile(default_ip_gen=ip_gen, cap_list=[
            ASTFCapInfo(file="/opt/trex/avl/delay_10_http_get_0.pcap", cps=102.0,port=8080),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_http_post_0.pcap", cps=102.0,port=8081),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_https_0.pcap", cps=33.0),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_http_browsing_0.pcap", cps=179.0),


            ASTFCapInfo(file="/opt/trex/avl/delay_10_exchange_0.pcap", cps=64.0),

            ASTFCapInfo(file="/opt/trex/avl/delay_10_mail_pop_0.pcap", cps=1.2),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_mail_pop_1.pcap", cps=1.2,port=111),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_mail_pop_2.pcap", cps=1.2,port=112),

            ASTFCapInfo(file="/opt/trex/avl/delay_10_oracle_0.pcap", cps=20.0),

            ASTFCapInfo(file="/opt/trex/avl/delay_10_rtp_160k_0.pcap", cps=0.7),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_rtp_160k_1.pcap", cps=0.7),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_rtp_250k_0_0.pcap", cps=0.5),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_rtp_250k_1_0.pcap", cps=0.5),

            ASTFCapInfo(file="/opt/trex/avl/delay_10_smtp_0.pcap", cps=1.85),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_smtp_1.pcap", cps=1.85,port=26),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_smtp_2.pcap", cps=1.85,port=27),

            ASTFCapInfo(file="/opt/trex/avl/delay_10_video_call_0.pcap", cps=3),

            ASTFCapInfo(file="/opt/trex/avl/delay_10_video_call_rtp_0.pcap", cps=7.4),

            ASTFCapInfo(file="/opt/trex/avl/delay_10_citrix_0.pcap", cps=11.0),

            ASTFCapInfo(file="/opt/trex/avl/delay_10_dns_0.pcap", cps=498.0),

            ASTFCapInfo(file="/opt/trex/avl/delay_10_sip_0.pcap", cps=7.4),
            ASTFCapInfo(file="/opt/trex/avl/delay_10_rtsp_0.pcap", cps=1.2),

        ])

        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(file)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        args, unknown = parser.parse_known_args(tunables)
        if unknown:
            raise Exception('unrecognized arguments {0}\n{1}'.format(unknown, parser.format_usage()))
        return self.create_profile()


def register():
    return Prof1()
