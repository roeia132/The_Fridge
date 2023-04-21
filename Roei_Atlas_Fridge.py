# Roei Atlas
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether, ARP


def dhcp_offer(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        client_mac = pkt[Ether].src
        client_mac_bytes = bytes(int(b, 16) for b in client_mac.split(':'))
        server_mac = "00:50:56:c0:00:0f"
        server_ip = "10.0.0.1"
        offer_ip = "10.0.0.10"
        trans_id = pkt[BOOTP].xid
        dhcp_offer_pkt = Ether(src=server_mac, dst=client_mac) / IP(src=server_ip, dst=offer_ip) / UDP(
            sport=67, dport=68) / BOOTP(op=2, htype=pkt[BOOTP].htype, hlen=pkt[BOOTP].hlen, hops=pkt[BOOTP].hops,
                                        xid=trans_id, secs=pkt[BOOTP].secs, ciaddr=pkt[BOOTP].ciaddr, yiaddr=offer_ip,
                                        siaddr=server_ip, giaddr=pkt[BOOTP].giaddr,
                                        chaddr=client_mac_bytes + b'\x00' * 10) / \
                         DHCP(options=[('message-type', 'offer'), ('server_id', server_ip), ('lease_time', 86400),
                                       ('subnet_mask', '255.255.255.0'), ('broadcast_address', '10.0.0.255'),
                                       ('name_server', server_ip), ('router', server_ip), 'end'])
        sendp(dhcp_offer_pkt, iface="VMware Network Adapter VMnet15")


def dhcp_ack(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 3:
        client_mac = pkt[Ether].src
        client_mac_bytes = bytes(int(b, 16) for b in client_mac.split(':'))
        server_mac = "00:50:56:c0:00:0f"
        server_ip = "10.0.0.1"
        offer_ip = "10.0.0.10"
        trans_id = pkt[BOOTP].xid
        dhcp_ack_pkt = Ether(src=server_mac, dst=client_mac) / IP(tos=pkt[IP].tos, src=server_ip, dst=offer_ip) / UDP(
            sport=67, dport=68) / BOOTP(op=2, htype=pkt[BOOTP].htype, hlen=pkt[BOOTP].hlen, hops=pkt[BOOTP].hops,
                                        xid=trans_id, secs=pkt[BOOTP].secs, ciaddr=pkt[BOOTP].ciaddr, yiaddr=offer_ip,
                                        siaddr=server_ip, giaddr=pkt[BOOTP].giaddr,
                                        chaddr=client_mac_bytes + b'\x00' * 10) / \
                       DHCP(options=[('message-type', 'ack'), ('server_id', server_ip), ('lease_time', 86400),
                                     ('subnet_mask', '255.255.255.0'), ('broadcast_address', '10.0.0.255'),
                                     ('name_server', server_ip), ('NetBIOS_server', server_ip),
                                     ('router', server_ip), 'end'])
        sendp(dhcp_ack_pkt, iface="VMware Network Adapter VMnet15")


def arp_reply(pkt):
    if ARP in pkt and pkt[ARP].op == 1:
        src_mac = pkt[ARP].hwsrc
        src_ip = pkt[ARP].psrc
        my_server_mac = "00:50:56:c0:00:0f"
        my_server_ip = "10.0.0.1"
        arp_reply_pkt = Ether(src=my_server_mac, dst=src_mac) / ARP(op=2, hwsrc=my_server_mac, psrc=my_server_ip,
                                                                    hwdst=src_mac, pdst=src_ip)
        sendp(arp_reply_pkt, iface="VMware Network Adapter VMnet15")


def dns_query_handler(pkt):
    if pkt[DNS].arcount == 0:
        b_site_add = pkt[DNS][DNSQR].qname
        dns_response_pkt = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) \
                           / IP(src=pkt[IP].dst, dst=pkt[IP].src) \
                           / UDP(dport=pkt[UDP].sport, sport=53) \
                           / DNS(id=pkt[DNS].id, qr=1, rd=1, ra=0, qd=DNSQR(qname=b_site_add),
                                 an=DNSRR(rrname=b_site_add, rdata="10.0.0.1", type="A", ttl=60, rclass="IN",
                                          rdlen=4))
        sendp(dns_response_pkt, iface="VMware Network Adapter VMnet15")


def tcp_syn_ack(pkt):
    ack_val = pkt[TCP].seq + 1
    syn_ack_response = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / \
                       IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                       TCP(sport=80, dport=pkt[TCP].sport, flags="SA", seq=1000, ack=ack_val,
                           options=[('MSS', 1452), ('SAckOK', b''), ('Timestamp', (4141161989, 0)), ('NOP', None),
                                    ('WScale', 7)])
    sendp(syn_ack_response, iface="VMware Network Adapter VMnet15")


def http_response(pkt):
    http_content = "HTTP/1.1 200 OK\r\n" + \
                        "Content-Type: text/html\r\n" + \
                        "Content-Length: 0\r\n" + \
                        "\r\n" + \
                        "<html><body></body></html>"
    http_response_pkt = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                        TCP(sport=80, dport=pkt[TCP].sport, flags="A", seq=pkt[TCP].ack,
                            ack=pkt[TCP].seq + len(pkt[TCP].payload)) / http_content
    sendp(http_response_pkt, iface="VMware Network Adapter VMnet15")

    fin_ack_pkt = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                  TCP(sport=80, dport=pkt[TCP].sport, flags="FA", seq=pkt[TCP].ack + len(http_content),
                      ack=pkt[TCP].seq + len(pkt[TCP].payload))
    sendp(fin_ack_pkt, iface="VMware Network Adapter VMnet15")


def main_fridge():

    # DHCP Offer
    sniff(filter="udp and (port 67 or port 68)", prn=dhcp_offer, iface="VMware Network Adapter VMnet15", count=1)
    # DHCP Acknowledge
    sniff(filter="udp and (port 67 or port 68)", prn=dhcp_ack, iface="VMware Network Adapter VMnet15", count=1)
    # ARP Reply
    sniff(filter="arp", prn=arp_reply, iface="VMware Network Adapter VMnet15", count=1)
    # DNS Reply
    sniff(filter="host 10.0.0.10 and udp port 53", prn=dns_query_handler, iface="VMware Network Adapter VMnet15", count=5)
    # TCP Syn-Ack
    sniff(filter="host 10.0.0.10 and tcp port 80", prn=tcp_syn_ack, iface="VMware Network Adapter VMnet15", count=1)
    # HTTP Response 200
    sniff(filter="host 10.0.0.10 and tcp port 80", prn=http_response, iface="VMware Network Adapter VMnet15", count=1)


main_fridge()
