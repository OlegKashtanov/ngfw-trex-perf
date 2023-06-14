## How to use 

* Minimal Python version - 3.9.
```
./parse_emix_profile.py -f ../trex_profiles/emix_http_exchange_pop_oracle_rtp_smtp_citrix_dns_sip_rtsp.py -o emix.pcap
```
* Output example:
```
+----------------------------------------------+-------------------------+---------+----------------+-----------------------------------+
| Templates                                    | Bytes in one connection |   CPS   | TP (L2), bit/s | % of Total Traffic by bytes count |
+----------------------------------------------+-------------------------+---------+----------------+-----------------------------------+
| /opt/trex/avl/delay_10_http_get_0.pcap       |         35.3 kB         |  102.0  |  28.8 Mbit/s   |              12.58 %              |
| /opt/trex/avl/delay_10_http_post_0.pcap      |         45.4 kB         |  102.0  |  37.1 Mbit/s   |              16.17 %              |
| /opt/trex/avl/delay_10_https_0.pcap          |         86.2 kB         |   33.0  |  22.8 Mbit/s   |               9.93 %              |
| /opt/trex/avl/delay_10_http_browsing_0.pcap  |         32.3 kB         |  179.0  |  46.3 Mbit/s   |               20.2 %              |
| /opt/trex/avl/delay_10_exchange_0.pcap       |         7.48 kB         |   64.0  |  3.83 Mbit/s   |               1.67 %              |
| /opt/trex/avl/delay_10_mail_pop_0.pcap       |         4.48 kB         |   1.2   |  43.0 kbit/s   |               0.02 %              |
| /opt/trex/avl/delay_10_mail_pop_1.pcap       |         95.1 kB         |   1.2   |   913 kbit/s   |               0.4 %               |
| /opt/trex/avl/delay_10_mail_pop_2.pcap       |         13.9 kB         |   1.2   |   134 kbit/s   |               0.06 %              |
| /opt/trex/avl/delay_10_oracle_0.pcap         |         39.8 kB         |   20.0  |  6.36 Mbit/s   |               2.77 %              |
| /opt/trex/avl/delay_10_rtp_160k_0.pcap       |         94.5 kB         |   0.7   |   529 kbit/s   |               0.23 %              |
| /opt/trex/avl/delay_10_rtp_160k_1.pcap       |         1.08 MB         |   0.7   |  6.04 Mbit/s   |               2.63 %              |
| /opt/trex/avl/delay_10_rtp_250k_0_0.pcap     |          161 kB         |   0.5   |   643 kbit/s   |               0.28 %              |
| /opt/trex/avl/delay_10_rtp_250k_1_0.pcap     |         1.67 MB         |   0.5   |  6.68 Mbit/s   |               2.92 %              |
| /opt/trex/avl/delay_10_smtp_0.pcap           |         4.39 kB         |   1.85  |  64.9 kbit/s   |               0.03 %              |
| /opt/trex/avl/delay_10_smtp_1.pcap           |         16.4 kB         |   1.85  |   243 kbit/s   |               0.11 %              |
| /opt/trex/avl/delay_10_smtp_2.pcap           |         90.4 kB         |   1.85  |  1.34 Mbit/s   |               0.58 %              |
| /opt/trex/avl/delay_10_video_call_0.pcap     |         2.43 MB         |    3    |  58.4 Mbit/s   |              25.49 %              |
| /opt/trex/avl/delay_10_video_call_rtp_0.pcap |         40.7 kB         |   7.4   |  2.41 Mbit/s   |               1.05 %              |
| /opt/trex/avl/delay_10_citrix_0.pcap         |         69.7 kB         |   11.0  |  6.13 Mbit/s   |               2.67 %              |
| /opt/trex/avl/delay_10_dns_0.pcap            |          78.0 B         |  498.0  |   311 kbit/s   |               0.14 %              |
| /opt/trex/avl/delay_10_sip_0.pcap            |         2.37 kB         |   7.4   |   140 kbit/s   |               0.06 %              |
| /opt/trex/avl/delay_10_rtsp_0.pcap           |         2.99 kB         |   1.2   |  28.7 kbit/s   |               0.01 %              |
| Total:                                       |         6.03 MB         | 1039.55 |   229 Mbit/s   |               100 %               |
+----------------------------------------------+-------------------------+---------+----------------+-----------------------------------+
```
