#!/usr/bin/python3

# -*- coding: utf-8 -*-

from socket import *
import argparse
import threading
import multiprocessing



def serviceRunning(tgtIP, port, sock, result):
    """
    if port == 80:
        sock.send('GET HTTP/1.1 \r\n')
    else:
        sock.send('Hola')
    #results = sock.recv(4096).decode('utf-8')
    """
    if result == 0:
        print('[+] PORT: ' + str(port) + ' OPEN \n Service ')
    elif result == 111:
        print('[+] PORT: ' + str(port) + ' CLOSED')
    else:
        print(result)

def targetScanner(tgtIP, port_start, port_stop):

    for port in range(port_start, port_stop + 1):
        sock = socket(AF_INET, SOCK_STREAM)
        result = sock.connect_ex((tgtIP, port))
        print(result)
        serviceRunning(tgtIP, port, sock, result)
        sock.close()
        
threads = []

parser = argparse.ArgumentParser('TCP SCANNER:')
parser.add_argument('-i', '--address', type=str, help='Direccion IP destino')
parser.add_argument('-w', '--web', type=str, help='Web destino a escanear')

args = parser.parse_args()
ipaddress = args.address
web = args.web

ip = ""

if not ipaddress and web:
    ip = gethostbyname(web)
else:
    ip = ipaddress

portsPerThread = 500 / multiprocessing.cpu_count()
n_hilos = multiprocessing.cpu_count()

inicio = 0
final = 0

for i in range(n_hilos):
    inicio = i * portsPerThread + 1 
    final = inicio + (portsPerThread - 1)
    if i == n_hilos - 1:
        fin = 500
    threads.append(threading.Thread(target=targetScanner, args=(ip, int(inicio), int(final))).start())

print('Fin')
        
    