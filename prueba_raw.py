#!/usr/bin/python3

import socket, sys
from struct import *

def checksum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += data[i] + (data[i+1] << 8)  
    
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)

    s = ~s & 0xFFFF
    return s

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

def ip_packet():
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0
    ip_id = 0
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    return pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

def tcp_packet(tcp_dest):
    tcp_source = 1234
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    return pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

def tcp_packet2(tcp_dest, tcp_check):
    tcp_source = 1234
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    return pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + pack('H', tcp_check) + pack('H', tcp_urg_ptr)
    

if __name__ == '__main__':
    source_ip = '192.168.1.43'
    dest_ip = '192.168.1.1'

    user_data = 'Hello, how are you'

    ports = 500

    for port in range(ports):
        ip_header = ip_packet()
        tcp_header = tcp_packet(port)

        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(user_data.encode('utf-8'))

        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header + user_data.encode('utf-8')

        tcp_check = checksum(psh)

        tcp_header = tcp_packet2(port, tcp_check)

        packet = ip_header + tcp_header + user_data.encode('utf-8')

        s.sendto(packet, (dest_ip, 0))
        msg = s.recv(2048)
        print(msg)
    s.close()