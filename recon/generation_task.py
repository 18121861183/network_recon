#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by zhaoyaochen on 19-8-21
import datetime
import ipaddress
import os

from django.utils import timezone

from network_recon import settings
from recon import date_util, models
from recon.common import port_protocols, unfinished
from recon.hash_util import get_sha1


def ip_number(file):
    number = 0
    with open(file, 'r') as ips:
        for ip in ips.readlines():
            ip = ip.strip()
            number += ipaddress.ip_network(ip, False).num_addresses
    return number


def generation(file_path):
    if os.path.exists(file_path):
        ip_count = ip_number(file_path)
        name = str(date_util.get_now_timestamp())
        for port in port_protocols.keys():
            protocol_str = ""
            for protocol in port_protocols.get(port):
                if protocol in unfinished:
                    continue
                if protocol_str != "":
                    protocol_str += ","
                protocol_str += protocol
            file1 = settings.zmap_result_path + name + "_" + str(port) + ".csv"
            command = ['zmap', '-w', file_path, '--probe-module=icmp_echoscan', '-r', settings.fast_scan_rate, '-p', str(port), ' -c 2 | ztee', file1]
            com_str = " ".join(command)
            _id = get_sha1(com_str)
            models.ScanTask.objects.create(id=_id, command=com_str, port=port, protocol=protocol_str, ip_range="*", ip_count=ip_count,
                                           port_result_path=file1, issue_time=timezone.now(), execute_status=0, priority=1).save()


def generation_normal(file_path):
    if os.path.exists(file_path):
        ip_count = ip_number(file_path)
        name = str(date_util.get_now_timestamp())
        for port in port_protocols.keys():
            protocol_str = ""
            for protocol in port_protocols.get(port):
                if protocol in unfinished:
                    continue
                if protocol_str != "":
                    protocol_str += ","
                protocol_str += protocol
            file1 = settings.zmap_result_path + name + "_" + str(port) + ".csv"
            command = ['zmap', '-w', file_path, '--probe-module=icmp_echoscan', '-r', settings.normal_scan_rate, '-p', str(port), ' | ztee', file1]
            com_str = " ".join(command)
            _id = get_sha1(com_str)
            models.ScanTask.objects.create(id=_id, command=com_str, port=port, protocol=protocol_str, ip_range="*", ip_count=ip_count,
                                           port_result_path=file1, issue_time=timezone.now(), execute_status=0, priority=5).save()

