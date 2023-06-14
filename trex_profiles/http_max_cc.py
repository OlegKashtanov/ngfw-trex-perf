# create high number of flow using high delay
# Example: 
# start with '-m 1000000  -t delay=10000000'
# You should have at least 30M*2K(flow memory) free heap memory  = 60GB
#
# 1) you will need to add to trex_cfg.yaml
#
# memory    :
#        dp_flows    : 30000000
# 2) x_glob_info.tcp.delay_ack_msec = 4000 enlarge the tick time to 4 sec instead of 40msec
# this will help to support more flows in the price of less accurate timers
#
# 3)  ASTFIPGenDist(ip_range=["16.0.0.0", "16.0.100.255"] << more than 255 clients to support more active flows
#
# 4) reduce the keepalive
#        c_glob_info.tcp.keepinit = 5000
#        c_glob_info.tcp.keepidle = 5000
#        c_glob_info.tcp.keepintvl = 5000


from trex.astf.api import *
import argparse


class Prof1():
    def __init__(self):
        self.p1_src_start_ip = '10.0.0.1'
        self.p1_src_end_ip = '10.0.255.199'

        self.p1_dst_start_ip = '48.0.0.1'
        self.p1_dst_end_ip = '48.1.255.199'

        self.http_req = ('GET /index.html HTTP/1.1\r\n' \
                         'Host: {host}\r\n' \
                         'Connection: Keep-Alive\r\n' \
                         'User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)\r\n' \
                         'Accept: */*\r\n' \
                         'Accept-Language: en-us\r\n' \
                         'Accept-Encoding: gzip, deflate, compress\r\n' \
                         '\r\n'
                         .format(host=self.p1_dst_start_ip))

        self.http_response_template = 'HTTP/1.1 200 OK\r\n' \
                                      'Server: Microsoft-IIS/6.0\r\n' \
                                      'Content-Type: text/html\r\n' \
                                      'Content-Length: {0}\r\n' \
                                      '\r\n' \
                                      '<html><pre>{1}</pre></html>'

        self.response_body_tags_bytes = 24
        self.pipeline = 10


    def create_profile(self, resp_size, delay):

        http_response = self.http_response_template.format(resp_size, '*' * ( resp_size - self.response_body_tags_bytes ))
        # client commands
        prog_c = ASTFProgram()
        prog_c.set_var("i", self.pipeline)
        prog_c.set_label("a:")
        prog_c.send(self.http_req)
        prog_c.recv(len(http_response))
        prog_c.jmp_nz("i", "a:")
        # implicit  close

        # server commands
        prog_s = ASTFProgram()
        prog_s.set_var("i", self.pipeline)
        prog_s.set_label("a:")
        prog_s.recv(len(self.http_req))
        # Delay in usec
        prog_s.delay(delay * 1000000)
        prog_s.send(http_response)
        prog_s.jmp_nz("i", "a:")
        prog_s.wait_for_peer_close()

        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=[self.p1_src_start_ip, self.p1_src_end_ip], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=[self.p1_dst_start_ip, self.p1_dst_end_ip], distribution="seq")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        # template
        temp_c = ASTFTCPClientTemplate(program=prog_c, ip_gen=ip_gen, limit=30000000)
        temp_s = ASTFTCPServerTemplate(program=prog_s)  # using default association
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)

        # Set rx/tx buffer to 64K. TCP window size also will be 64K
        c_glob_info = ASTFGlobalInfo()
        c_glob_info.tcp.rxbufsize = 65535
        c_glob_info.tcp.txbufsize = 65535

        ## Increase tcp timeouts 
        c_glob_info.tcp.keepinit = 5000
        c_glob_info.tcp.keepidle = 5000
        c_glob_info.tcp.keepintvl = 5000
        c_glob_info.tcp.delay_ack_msec = 4000
        
        s_glob_info = ASTFGlobalInfo()
        s_glob_info.tcp.rxbufsize = 65535
        s_glob_info.tcp.txbufsize = 65535

        ## Increase tcp timeouts 
        s_glob_info.tcp.keepinit = 5000
        s_glob_info.tcp.keepidle = 5000
        s_glob_info.tcp.keepintvl = 5000
        s_glob_info.tcp.delay_ack_msec = 4000

        # profile
        return ASTFProfile(default_ip_gen=ip_gen,
                           default_c_glob_info=c_glob_info,
                           default_s_glob_info=s_glob_info,
                           templates=template)

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--size',
                            type=int,
                            default=1,
                            help='The response size in KB')
        parser.add_argument('--delay',
                            type=int,
                            default=30,
                            help='Delay between transactions in sec')
        args, unknown = parser.parse_known_args(tunables)
        if unknown:
            raise Exception('unrecognized arguments {0}\n{1}'.format(unknown, parser.format_usage()))
        resp_size = args.size * 1024
        return self.create_profile(resp_size, args.delay)


def register():
    return Prof1()
