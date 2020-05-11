#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by zhaoyaochen on 19-8-12
import MySQLdb
import datetime
import os

from recon.common import port_protocols, unfinished
from recon.hash_util import get_sha1


# config = dict()
# BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# print(BASE_DIR)
# with open(BASE_DIR+'/task_utils/config.properties', 'r') as cfp:
#     for line in cfp.readlines():
#         if line.startswith('#'):
#             continue
#         else:
#             info = line.strip().split("=")
#             if len(info) == 2:
#                 config[info[0].strip()] = info[1].strip()

db = MySQLdb.connect(host="192.168.0.13", user="root",
                     port="3306", passwd="colasoft@CSDP", db="recon")
client = db.cursor()


ip_count = 65535
for port in port_protocols.keys():
    for protocol in port_protocols.get(port):
        if protocol in unfinished:
            continue
        # if protocol_str != "":
        #     protocol_str += ","
        # protocol_str += protocol
        file1 = '/opt/recon/zmap/172.16.0.0_' + str(protocol) + "_" + str(port) + ".csv"
        file2 = '/opt/recon/zgrab/172.16.0.0_' + str(protocol) + "_" + str(port) + ".json"
        command = ['zmap', '172.16.0.0/16', '--probe-module=icmp_echoscan', '-r',
                   '2000', '-p', str(port), ' --output-fields=* | ztee', file1, '| zgrab2',
                   protocol, '-p', str(port), '--output-file=' + file2]
        com_str = " ".join(command)
        _id = get_sha1(com_str)
        dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        insert = "INSERT INTO client_scantask VALUES" \
                 "('{}', '{}', {}, '{}', '{}', {}, 0, '{}', '{}', " \
                 "NULL, NULL, NULL, 0, 0, 0, -1, {})" \
            .format(_id, com_str, port, "", "*", ip_count, file1, dt, 5)

        print(insert)

        client.execute(insert)
    db.commit()

