#!/usr/bin/env python

import os
import sys
import socket
import threading
from collections import Counter

import pytrap
import numpy as np
import matplotlib.pyplot as plt

trap = pytrap.TrapCtx()
trap.init(sys.argv, 1, 0)

SOCK_PATH = '/var/run/libtrap/munin_tls_traffic'

# Create maps for statistics
tls_server_ver_flows = Counter()
tls_client_ver_flows = Counter()
tls_server_ver_bytes = Counter()
tls_client_ver_bytes = Counter()
tls_server_ver_packets = Counter()
tls_client_ver_packets = Counter()
tls_extensions = Counter()
cnt_not_tls = 0
cnt_tls = 0

def accept_connections(socket_path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        try:
            if os.path.exists(socket_path):
                os.remove(socket_path)
            sock.bind(socket_path)
            sock.listen(1)
        except OSError as msg:
            sock.close()
            raise
        while True:
            conn, addr = sock.accept()
            with conn:
                fields_title = ','.join(
                    [  '{}-{}'.format(v, t)
                        for v in ['sslv3', 'tlsv1_0', 'tlsv1_1', 'tlsv1_2', 'tlsv1_3']
                        for t in ['flows', 'bytes', 'packets']
                        ]
                )
                fields_values = ','.join(
                    [  '{}'.format(t[v])
                        for v in [768, 769, 770, 771, 772]
                        for t in [tls_server_ver_flows, tls_server_ver_bytes, tls_server_ver_packets]
                        ]
                )

                conn.send(fields_title.encode('utf-8'))
                conn.send("\n".encode('utf-8'))

                conn.send(fields_values.encode('utf-8'))
                conn.send("\n".encode('utf-8'))
            # the conn is closed here
        pass

thread1 = threading.Thread(target = accept_connections, args = (SOCK_PATH,))
thread1.start()

# Set the list of required fields in received messages.
# This list is an output of e.g. flow_meter - basic flow.
inputspec = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint64 TLS_SETUP_TIME,int64 TLS_VALIDITY_NOTAFTER,int64 TLS_VALIDITY_NOTBEFORE,uint32 PACKETS,int32 TLS_CLIENT_KEYLENGTH,uint32 TLS_HANDSHAKE_TYPE,int32 TLS_PUBLIC_KEYLENGTH,uint16 DST_PORT,uint16 SRC_PORT,uint16 TLS_CIPHER_SUITE,uint16 TLS_CLIENT_VERSION,uint16 TLS_PUBLIC_KEYALG,uint16 TLS_SERVER_VERSION,uint16 TLS_SIGNATURE_ALG,uint16 TLS_SNI_LENGTH,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TLS_CONTENT_TYPE,string TLS_ALPN,bytes TLS_CIPHER_SUITES,bytes TLS_CLIENT_RANDOM,bytes TLS_CLIENT_SESSIONID,bytes TLS_EC_POINTFORMATS,bytes TLS_ELLIPTIC_CURVES,bytes TLS_EXTENSION_LENGTHS,bytes TLS_EXTENSION_TYPES,string TLS_ISSUER_CN,bytes TLS_JA_3FINGERPRINT,bytes TLS_SERVER_RANDOM,bytes TLS_SERVER_SESSIONID,string TLS_SNI,string TLS_SUBJECT_CN,string TLS_SUBJECT_ON"
trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
rec = pytrap.UnirecTemplate(inputspec)

def do_detection(rec):
    global tls_server_ver, tls_client_ver, cnt_tls, cnt_not_tls, tls_extensions
    
    # check if it's not empty
    if rec.TLS_CIPHER_SUITES.rstrip(b'\x00'):

        #print(rec.TLS_CIPHER_SUITES)
        is_tlsv13 = False
        cnt_tls += 1

        # iterate through extensions
        ext_len = len(rec.TLS_EXTENSION_TYPES)
        i = 0
        while i < ext_len:
            ext_type = rec.TLS_EXTENSION_TYPES[i:i+2]
            if ext_type == b'\xff\xff':
                break
            if ext_type == b'\x2b\x00': # supported_versions extension
                # potentially TLS v1.3
                # TODO we need a further differentiator
                tls_server_ver_flows[772] += 1
                tls_server_ver_bytes[772] += rec.BYTES
                tls_server_ver_packets[772] += rec.PACKETS
                pass
            tls_extensions[str(ext_type)] += 1
            i+=2
        
        if not is_tlsv13:
            tls_server_ver_flows[rec.TLS_SERVER_VERSION] += 1
            tls_client_ver_flows[rec.TLS_CLIENT_VERSION] += 1
            tls_server_ver_bytes[rec.TLS_SERVER_VERSION] += rec.BYTES
            tls_client_ver_bytes[rec.TLS_CLIENT_VERSION] += rec.BYTES
            tls_server_ver_packets[rec.TLS_SERVER_VERSION] += rec.PACKETS
            tls_client_ver_packets[rec.TLS_CLIENT_VERSION] += rec.PACKETS

    else:
        cnt_not_tls += 1

# Main loop
while True:
    try:
        data = trap.recv()
    except pytrap.FormatChanged as e:
        fmttype, inputspec = trap.getDataFmt(0)
        rec = pytrap.UnirecTemplate(inputspec)
        data = e.data
    if len(data) <= 1:
        break
    rec.setData(data)

    do_detection(rec)

# Free allocated TRAP IFCs
trap.finalize()