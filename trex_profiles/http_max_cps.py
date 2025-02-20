from trex.astf.api import *
import argparse


http_req = 'GET /index.html HTTP/1.1\r\n' \
           'Host: 22.0.0.3\r\n' \
           'Connection: Close\r\n' \
           'User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)\r\n' \
           'Accept: */*\r\n' \
           'Accept-Language: en-us\r\n' \
           'Accept-Encoding: gzip, deflate, compress\r\n' \
           '\r\n'

http_response_headers = 'HTTP/1.1 200 OK\r\n' \
                         'Server: Microsoft-IIS/6.0\r\n' \
                         'Content-Type: text/html\r\n' \
                         'Content-Length: {0}\r\n' \
                         '\r\n'

http_response_body = '<html><pre>{0}</pre></html>'

RESPONSE_BODY_TAGS_BYTES = 24


class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self, resp_body_size, delay, ramp_up):
        if resp_body_size > 24:
            http_response = http_response_headers.format(resp_body_size) + \
                            http_response_body.format('*' * (resp_body_size - RESPONSE_BODY_TAGS_BYTES))
        else:
            http_response = http_response_headers.format(resp_body_size) + '*' * resp_body_size
        # client commands
        prog_c = ASTFProgram()
        prog_c.send(http_req)
        prog_c.recv(len(http_response))
        # implicit  close

        # server commands
        prog_s = ASTFProgram()
        prog_s.recv(len(http_req))
        if delay: prog_s.delay(delay)
        prog_s.send(http_response)
        prog_s.wait_for_peer_close()

        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["10.0.0.1", "10.0.255.199"], distribution="rand")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.1", "48.1.255.199"], distribution="rand")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)

        # template
        temp_c = ASTFTCPClientTemplate(program=prog_c, ip_gen=ip_gen)
        temp_s = ASTFTCPServerTemplate(program=prog_s)  # using default association
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)

        # Set rx/tx buffer to 64K. TCP window size also will be 64K
        c_glob_info = ASTFGlobalInfo()
        c_glob_info.tcp.rxbufsize = 65535
        c_glob_info.tcp.txbufsize = 65535
        if ramp_up: c_glob_info.scheduler.rampup_sec = ramp_up
        s_glob_info = ASTFGlobalInfo()
        s_glob_info.tcp.rxbufsize = 65535
        s_glob_info.tcp.txbufsize = 65535

        # profile
        profile = ASTFProfile(default_ip_gen=ip_gen,
                              default_c_glob_info=c_glob_info,
                              default_s_glob_info=s_glob_info,
                              templates=template)
        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--response_size_kb',
                            type=float,
                            default=1,
                            help='The response size in KB')
        parser.add_argument('--delay',
                            type=int,
                            default=None,
                            help='Server response delay (usec)')
        parser.add_argument('--ramp_up',
                            type=int,
                            default=0,
                            help='Ramp up period (sec)')
        args, unknown = parser.parse_known_args(tunables)
        if unknown:
            raise Exception('unrecognized arguments {0}\n{1}'.format(unknown, parser.format_usage()))
        resp_size = int(args.response_size_kb * 1024)
        return self.create_profile(resp_size, args.delay, args.ramp_up)


def register():
    return Prof1()
