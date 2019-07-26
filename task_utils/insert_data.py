#!/usr/bin/python
# coding:utf-8

"""
@author: zyc
@contact: yaochen.zhao@colasoft.com.cn
@software: PyCharm
@file: insert_data.py
@time: 2019/7/1 15:16
"""
import datetime
import hashlib
import os
import ipaddress

import MySQLdb

from recon.common import port_protocols, unfinished, foreign_protocols

config = dict()
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(BASE_DIR)
with open(BASE_DIR+'/task_utils/config.properties', 'r') as cfp:
    for line in cfp.readlines():
        if line.startswith('#'):
            continue
        else:
            info = line.strip().split("=")
            if len(info) == 2:
                config[info[0].strip()] = info[1].strip()

db = MySQLdb.connect(host=config.get("mysql_host"), user=config.get("mysql_user"),
                     port=int(config.get("mysql_port")), passwd=config.get("mysql_passwd"),
                     db=config.get("mysql_db"))
client = db.cursor()

wf = config.get("zmap_white_path")
if wf.endswith("/") is False:
    wf = wf + "/"

model = config.get("file_model")

# with open(config.get("scan_file"), "r") as all_ips:
#     count = 1
#     file_number = 1
#     file_name = datetime.datetime.now().strftime("%Y%m%d%H%M%S_")
#     _outfile = open(wf+file_name+str(file_number), 'w')
#     max_number = int(config.get("record_max_ips"))
#     print("开始分解要扫描的IP列表...")
#     if model == 'single':
#         for line in all_ips.readlines():
#             if count != 0 and count > max_number:
#                 _outfile.close()
#                 file_number += 1
#                 count = 0
#                 _outfile = open(wf+file_name+str(file_number), 'w')
#             line = line.strip()
#             _outfile.write(line+"\n")
#             number = ipaddress.ip_network(line, False).num_addresses
#             count += number
#     elif model == 'double':
#         for line in all_ips.readlines():
#             line = line.strip()
#             array = line.split(",")
#             if len(array) != 2:
#                 continue
#             for ip_num in range(int(ipaddress.IPv4Address(array[0])), int(ipaddress.IPv4Address(array[1]))+1):
#                 if count != 0 and count >= max_number:
#                     _outfile.close()
#                     file_number += 1
#                     count = 0
#                     _outfile = open(wf + file_name + str(file_number), 'w')
#                     print("生成指令文件：", file_name, file_number)
#                 _outfile.write(str(ipaddress.ip_address(int(ip_num)))+"\n")
#                 count += 1


zmap_path = config.get("zmap_result_path")
if zmap_path.endswith("/") is False:
    zmap_path = zmap_path + "/"


def get_sha1(_str):
    hash = hashlib.sha1()
    hash.update(_str.encode('utf-8'))
    return str(hash.hexdigest())


def ip_number(file):
    number = 0
    with open(file, 'r') as ips:
        for ip in ips.readlines():
            ip = ip.strip()
            number += ipaddress.ip_network(ip, False).num_addresses
    return number


priority = config.get("priority")

if config.get("ports") == "default":
    # 国内IP扫描常用指令生成
    for name in os.listdir(wf):
        ip_count = ip_number(wf + name)
        for port in port_protocols.keys():
            protocol_str = ""
            for protocol in port_protocols.get(port):
                if protocol in unfinished:
                    continue
                if protocol_str != "":
                    protocol_str += ","
                protocol_str += protocol
            file1 = zmap_path + name + ".csv"
            command = ['zmap', '-w', wf+name, '--probe-module=icmp_echoscan', '-r',
                       config.get("network_send_rate"), '-p', str(port),
                       ' | ztee', file1]
            com_str = " ".join(command)
            _id = get_sha1(com_str)
            dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            insert = "INSERT INTO recon_scantask VALUES" \
                     "('{}', '{}', {}, '{}', '{}', {}, 0, '{}', '{}', " \
                     "NULL, NULL, NULL, 0, 0, 0, -1, {})" \
                .format(_id, com_str, port, protocol_str, "*", ip_count, file1, dt, priority)

            print(insert)

            client.execute(insert)
            db.commit()
elif config.get("ports") == "foreign":
    # 国外IP常用选项
    for name in os.listdir(wf):
        ip_count = ip_number(wf + name)
        for port in foreign_protocols.keys():
            for protocol in foreign_protocols.get(port):
                if protocol in unfinished:
                    continue
                file1 = zmap_path + name + ".csv"
                command = ['zmap', '-w', wf + name, '--probe-module=icmp_echoscan', '-r',
                           config.get("network_send_rate"), '-p', str(port),
                           ' | ztee', file1]
                com_str = " ".join(command) + protocol
                _id = get_sha1(com_str)
                dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                insert = "INSERT INTO recon_scantask VALUES" \
                         "('{}', '{}', {}, '{}', '{}', {}, 0, '{}', '{}', " \
                         "NULL, NULL, NULL, 0, 0, 0, -1, {})" \
                    .format(_id, com_str, port, protocol, "*", ip_count, file1, dt, priority)

                print(insert)

                client.execute(insert)
                db.commit()
else:
    ports = config.get("ports").split(",")
    protocols = config.get("protocols").split(",")
    for name in os.listdir(wf):
        ip_count = ip_number(wf+name)
        for port, protocol in zip(ports, protocols):
            file1 = zmap_path+name+".csv"
            command = ['zmap', '-w', wf+name, '--probe-module=icmp_echoscan', '-r',
                       config.get("network_send_rate"), '-p', str(port),
                       ' | ztee', file1]
            com_str = " ".join(command) + protocol
            _id = get_sha1(com_str)
            dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            insert = "INSERT INTO recon_scantask VALUES" \
                     "('{}', '{}', {}, '{}', '{}', {}, 0, '{}', '{}', " \
                     "NULL, NULL, NULL, 0, 0, 0, -1, {})"\
                .format(_id, com_str, port, protocol, "*", ip_count, file1, dt, priority)

            print(insert)

            client.execute(insert)
            db.commit()

db.close()
