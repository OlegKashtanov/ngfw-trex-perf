
from trex.astf.api import *
import argparse


UDP_REQ_BASE = 'x'
UDP_RESP_BASE = 'y'
FCS = 4
ETHER_HEADER = 14
IP_HEADER = 20
UDP_HEADER = 8
FRAME_HEADERS = FCS + ETHER_HEADER + IP_HEADER + UDP_HEADER
PIPELINE = 500
DELAY = 5000

class Prof1():
    def __init__(self):
        pass  # tunables

    #def create_profile(self, frame_size, limit):
    def create_profile(self, frame_size):

        # client commands
        udp_req = UDP_REQ_BASE * (frame_size - FRAME_HEADERS)
        prog_c = ASTFProgram(stream=False)
        for i in range(0, PIPELINE):
            prog_c.send_msg(udp_req)
            prog_c.recv_msg(1)
        
        udp_resp = UDP_RESP_BASE * (frame_size - FRAME_HEADERS)
        prog_s = ASTFProgram(stream=False)
        for i in range(0, PIPELINE):
            prog_s.recv_msg(1)
            prog_s.delay(DELAY)
            prog_s.send_msg(udp_resp)

        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["10.0.0.1", "10.0.255.199"], distribution="rand")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.1", "48.1.255.199"], distribution="rand")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)


        # template
        assoc=ASTFAssociationRule(port=53)
        temp_c = ASTFTCPClientTemplate(program=prog_c, ip_gen=ip_gen, port=53)
        temp_s = ASTFTCPServerTemplate(program=prog_s, assoc=assoc)
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)
        # Set rx/tx buffer
        c_glob_info = ASTFGlobalInfo()
        c_glob_info.tcp.rxbufsize = 1000000
        c_glob_info.tcp.txbufsize = 1000000
        s_glob_info = ASTFGlobalInfo()
        s_glob_info.tcp.rxbufsize = 1000000
        s_glob_info.tcp.txbufsize = 1000000
        # profile
        profile = ASTFProfile(default_ip_gen=ip_gen,
                              default_c_glob_info=c_glob_info,
                              default_s_glob_info=s_glob_info,
                              templates=template)
        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--size',
                            type=int,
                            default=64,
                            help='Frame size')
        args = parser.parse_args(tunables)
        frame_size = args.size
        return self.create_profile(frame_size)


def register():
    return Prof1()
