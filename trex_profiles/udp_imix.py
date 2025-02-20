from trex.astf.api import *
import argparse

UDP_REQ_BASE = 'x'
UDP_RESP_BASE = 'y'
FCS = 4
ETHER_HEADER = 14
IP_HEADER = 20
UDP_HEADER = 8
FRAME_HEADERS = FCS + ETHER_HEADER + IP_HEADER + UDP_HEADER


class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, ramp_up, frame_size, delay, flow_size):

        # client commands
        udp_req = UDP_REQ_BASE * (frame_size - FRAME_HEADERS)
        prog_c = ASTFProgram(stream=False)
        for i in range(0, int(flow_size / 2)):
            prog_c.send_msg(udp_req)
            prog_c.recv_msg(1)

        udp_resp = UDP_RESP_BASE * (frame_size - FRAME_HEADERS)
        prog_s = ASTFProgram(stream=False)
        for i in range(0, int(flow_size / 2)):
            prog_s.recv_msg(1)
            if delay: prog_s.delay(delay)
            prog_s.send_msg(udp_resp)

        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["10.0.0.1", "10.0.255.199"], distribution="rand")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.1", "48.1.255.199"], distribution="rand")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        # template
        assoc = ASTFAssociationRule(port=53)
        temp_c = ASTFTCPClientTemplate(program=prog_c, ip_gen=ip_gen, port=53)
        temp_s = ASTFTCPServerTemplate(program=prog_s, assoc=assoc)
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)
        # Set rx/tx buffer
        c_glob_info = ASTFGlobalInfo()
        c_glob_info.tcp.rxbufsize = 1000000
        c_glob_info.tcp.txbufsize = 1000000
        if ramp_up: c_glob_info.scheduler.rampup_sec = ramp_up
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
        parser.add_argument('--frame_size_b',
                            type=int,
                            default=64,
                            help='Frame size with FCS, bytes')
        parser.add_argument('--delay',
                            type=int,
                            default=None,
                            help='Server response delay (usec)')
        parser.add_argument('--flow_size',
                            type=int,
                            default=2,
                            help='Flow size (packets)')
        parser.add_argument('--ramp_up',
                            type=int,
                            default=0,
                            help='Ramp up period (sec)')
        args, unknown = parser.parse_known_args(tunables)
        if unknown:
            raise Exception('unrecognized arguments {0}\n{1}'.format(unknown, parser.format_usage()))
        return self.create_profile(args.ramp_up, args.frame_size_b, args.delay, args.flow_size)


def register():
    return Prof1()
