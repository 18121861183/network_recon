import hashlib
import io
import json
import os
import subprocess
import tarfile
import time
import uuid

import requests
import urllib3
from concurrent.futures import thread

from django.shortcuts import render

# Create your views here.
from django.utils import timezone

from network_recon import settings
from recon import models, date_util, hash_util

urllib3.disable_warnings()

default_protocol = ["ftp", "ssh", "telnet", "smtp", "pop3", "http", "fox", "bacnet",
                    "dnp3", "imap", "ipp", "modbus", "mongodb", "mssql", "mysql", "ntp",
                    "oracle", "postgres", "redis", "siemens", "smb", "amqp", "vnc", "dns",
                    "ipmi", "ldap", "rdp", "rpc", "rsync", "sip", "snmp", "tftp"]

us_ports = [21, 22, 23, 25, 80, 110, 137, 139, 161, 443, 445, 515, 1433, 1900, 3306,
            3389, 6379, 7547, 8080, 9200, 22105, 37777]


normal_ports = [13, 21, 22, 23, 25, 26, 53, 69, 80, 81, 88, 110, 111, 123, 135, 137,
                139, 161, 179, 264, 389, 443, 445, 465, 515, 520, 623, 636, 873, 902,
                992, 993, 995, 1234, 1241, 1433, 1521, 1604, 1701, 1900, 1967, 2181,
                3000, 3128, 3260, 3306, 3307, 3388, 3389, 4000, 4730, 5000, 5001,
                5060, 5353, 5357, 5400, 5555, 5672, 5900, 5938, 5984, 6000, 6379,
                6665, 6666, 6667, 6668, 6669, 7474, 7547, 7777, 8000, 8080, 8081, 8087,
                8089, 8834, 9200, 9999, 10000, 12345, 14000, 22105, 27017, 37777, 50000, 50100, 61613]


# portmap暂未实现, decrpc未实现, netbios未实现, bgp未实现,
# firewall-1未实现, lpd未实现, rip未实现, l2tv未实现, upnp未实现,
# zookeeper未实现, iscsi未实现, gearman未实现, mdns未实现, elastic未实现
# teamviewer未实现, x11未实现, irc未实现, dahua-dvr未实现, upnp未实现
# db2未实现, stomp, rifa-dvr, vmware_authentication_daemon
unfinished = ["netbios", "netbios-ssn", "bgp", "firewall-1",
              "lpd", "rip", "vmware_authentication_daemon", "l2tv", "upnp", "zookeeper",
              "iscsi", "gearman", "mdns", "teamviewer", "x11", "irc", "elastic", "db2",
              "dahua-dvr", "rifa-dvr", "stomp"]
port_protocols = {
    13: ["daytime", "ssh", "http"],
    21: ["ftp", "http", "ssh"],
    22: ["ssh", "http", "ftp"],
    23: ["telnet", "http", "ssh"],
    25: ["smtp", "http", "ftp"],
    26: ["smtp", "http", "ssh"],
    53: ["dns", "http", "ssh"],
    69: ["tftp", "http", "ssh"],
    80: ["http", "ssh", "ftp"],
    81: ["http", "ssh", "ftp"],
    88: ["http", "ssh", "ftp"],
    110: ["pop3", "http", "ssh"],
    111: ["portmap", "ssh", "http"],
    123: ["ntp", "http", "ssh"],
    135: ["dcerpc", "http", "ssh"],
    137: ["netbios", "http", "ssh"],
    139: ["netbios-ssn", "http", "ssh"],
    161: ["snmp", "http", "ssh"],
    179: ["bgp", "http", "ssh"],
    264: ["firewall-1", "http", "ssh"],
    389: ["ldap", "http", "ssh"],
    443: ["http", "ssh"],
    445: ["smb", "http"],
    465: ["smtp", "http"],
    515: ["lpd", "http", "ssh"],
    520: ["rip", "http", "ssh", "ftp"],
    623: ["ipmi", "http", "ssh", "ftp"],
    636: ["ldap", "http", "ssh"],
    873: ["rsync", "http", "ssh"],
    902: ["vmware_authentication_daemon", "http", "ftp"],
    992: ["http", "telnet", "ssh", "ftp"],
    993: ["imap", "http", "ssh", "ftp"],
    995: ["pop3", "http", "ssh"],
    1234: ["http", "ssh", "ftp"],
    1241: ["http", "ssh", "ftp"],
    1433: ["mssql", "http", "ssh"],
    1521: ["oracle", "http", "ftp"],
    1604: ["http", "ssh", "ftp"],
    1701: ["l2tv", "http", "ssh", "ftp"],
    1900: ["http", "upnp", "ssh"],
    1967: ["http", "ssh", "ftp"],
    2181: ["zookeeper", "http", "ssh"],
    3000: ["http", "ssh", "ftp"],
    3128: ["http", "ssh", "ftp"],
    3260: ["iscsi", "http", "ssh"],
    3306: ["mysql", "http", "ssh"],
    3307: ["mysql", "http", "ssh"],
    3388: ["rdp", "http", "ssh"],
    3389: ["rdp", "http", "ssh"],
    4000: ["http", "ssh", "ftp"],
    4730: ["http", "ssh", "gearman"],
    5000: ["http", "ssh"],
    5001: ["http", "ssh", "ftp"],
    5060: ["sip", "http", "ssh"],
    5353: ["mdns", "http", "ssh"],
    5357: ["http", "ssh", "ftp"],
    5400: ["http", "ssh", "ftp"],
    5555: ["http", "ssh"],
    5672: ["amqp", "http", "ssh"],
    5900: ["vnc", "http", "ssh"],
    5938: ["http", "teamviewer", "ssh"],
    5984: ["http", "ssh", "ftp"],
    6000: ["http", "ssh", "x11"],
    6379: ["redis", "http", "ssh"],
    6665: ["http", "ssh", "irc"],
    6666: ["http", "ssh", "irc"],
    6667: ["http", "ssh", "irc"],
    6668: ["http", "ssh", "irc"],
    6669: ["http", "ssh", "irc"],
    7474: ["http", "ssh", "ftp"],
    7547: ["http", "ssh", "ftp"],
    7777: ["http", "ssh", "ftp"],
    8000: ["http", "ssh"],
    8080: ["http", "ssh", "ftp"],
    8081: ["http", "ssh", "mysql"],
    8087: ["http", "ssh", "ftp"],
    8089: ["http", "ssh", "ftp"],
    8834: ["http", "ssh", "ftp"],
    9200: ["http", "ssh", "elastic"],
    9999: ["http", "ssh"],
    10000: ["http", "ssh"],
    12345: ["http", "ssh", "ftp"],
    14000: ["http", "ssh", "ftp"],
    22105: ["http", "ssh"],
    27017: ["http", "ssh", "mongodb"],
    37777: ["http", "ssh", "dahua-dvr"],
    50000: ["http", "ssh", "db2"],
    50100: ["http", "rifa-dvr", "ftp"],
    61613: ["http", "ssh", "stomp"]
}


ztag_command = {
    'ftp': '-P ftp -S banner',
    'ssh': '-P ssh -S v2',
    'telnet': '-P telnet -S banner',
    'smtp': '-P smtp -S starttls',
    'http': '-P http -S get',
    'pop3': '-P pop3 -S starttls',
    'smb': '-P smb -S banner',
    'imap': '-P imap -S starttls',
    'modbus': '-P modbus -S device_id',
    'mssql': '-P mssql -S banner',
    'oracle': '-P oracle -S banner',
    'fox': '-P fox -S device_id',
    'mysql': '-P mysql -S banner',
    'postgres': '-P postgres -S banner',
    'mongodb': '-P mongodb -S banner',
    'bacnet': '-P bacnet -S device_id',
    'dnp3': '-P dnp3 -S status',
}


def index(request):
    return render(request, "index.html")


def zmap_start(delay):
    task = models.ScanTask.objects.filter(execute_status=0).order_by('priority').first()
    if task is not None:
        models.ScanTask.objects.filter(id=task.id).update(execute_status=1)
        scan_start(task)
    time.sleep(delay)


def file_hash(file_path):
    m = hashlib.md5()
    _file = io.FileIO(file_path, 'r')
    _bytes = _file.read(1024)
    while _bytes != b'':
        m.update(_bytes)
        _bytes = _file.read(1024)
    _file.close()
    md5value = m.hexdigest()
    return md5value


def scan_start(task_info):
    command = task_info.command
    print("zmap running: ", command)

    try:
        subprocess.call(command, shell=True)
        count = 0
        with open(task_info.port_result_path, "r") as file:
            for _ in file.readlines():
                count += 1

        port = task_info.port
        task_number = 0
        for protocol in port_protocols.get(port):
            if protocol in unfinished:
                continue
            banner_command = ["zgrab2", "-f", task_info.port_result_path, protocol, "-p", str(port), "-t 5s"]
            _id = hash_util.get_md5(" ".join(banner_command))
            zgrab_result_path = settings.banner_save_path + protocol + "_" + str(port) + "_" + _id + ".json"
            ztag_result_path = None
            ztag_status = -1
            if protocol in ztag_command.keys():
                ztag_result_path = settings.ztag_save_path + protocol + "_" + str(port) + "_" + _id + ".json"
                ztag_status = 0
            banner_command.append('--output-file='+zgrab_result_path)
            models.BannerTask.objects.create(id=_id, command=" ".join(banner_command), port=port, protocol=protocol,
                                             ip_count=count, scan_task_id=task_info.id, banner_result_path=zgrab_result_path,
                                             ztag_result_path=ztag_result_path, ztag_status=ztag_status,
                                             priority=task_info.priority, create_time=timezone.now())
            task_number += 1

        models.ScanTask.objects.filter(id=task_info.id).update(execute_status=2, open_port_count=count, banner_task_count=task_number)
        models.ReconRecordLog.objects.create(id=uuid.uuid1(), ip_count=task_info.ip_count, command=command, success_count=count,
                                             task_type="online", create_time=timezone.now())
    except BaseException as e1:
        print(e1, command)
        models.ScanTask.objects.filter(id=task_info.id).update(execute_status=-1)


def exec_banner_job(delay):
    while True:
        print("exec_banner_job is running")
        task_info = models.BannerTask.objects.filter(execute_status=0).order_by('priority').first()
        if task_info is not None:
            models.BannerTask.objects.filter(id=task_info.id).update(execute_status=1)
            banner_start(task_info)
        time.sleep(delay)


def banner_start(task_info):
    command = task_info.command
    print("banner running: ", command)
    try:
        subprocess.call(command, shell=True)
        count = 0
        with open(task_info.banner_result_path, "r") as file:
            for line in file.readlines():
                if line.find('"error":"') == -1:
                    count += 1

        records_handled = 0
        ztag_status = -1
        if task_info.ztag_status == 0:
            ztag_status = 0
            shell_command = 'cat ' + task_info.banner_result_path + ' | ztag -p ' + str(task_info.port) + ' ' \
                            + ztag_command.get(task_info.protocol) + ' > ' + task_info.ztag_result_path
            output = subprocess.getoutput(shell_command)
            try:
                result = output.split("\n")
                if len(result) > 0:
                    _info = result[len(result)-1]
                    rh = json.loads(_info).get('records_handled')
                    if rh is not None:
                        records_handled = int(rh)
                ztag_status = 1
            except BaseException as e3:
                print(e3, "error ZTag info", shell_command)

        models.BannerTask.objects.filter(id=task_info.id).update(execute_status=2, banner_success_count=count, ztag_handle_count=records_handled,
                                                                 ztag_status=ztag_status, finish_time=timezone.now())
        scantask = models.ScanTask.objects.filter(id=task_info.scan_task_id).first()
        number = scantask.banner_task_count - 1
        models.ScanTask.objects.filter(id=task_info.scan_task_id).update(banner_task_count=number)
        models.ReconRecordLog.objects.create(id=uuid.uuid1(), ip_count=task_info.ip_count, command=command, success_count=count,
                                             task_type="banner", create_time=timezone.now())
    except BaseException as e1:
        print(e1, command)
        models.BannerTask.objects.filter(id=task_info.id).update(execute_status=-1)


def exec_finish_job(delay):
    while True:
        print("exec_finish_job is running")
        all_list = models.ScanTask.objects.filter(execute_status=2).filter(banner_task_count=0).all()
        if len(all_list) > 0:
            report_path = settings.report_save_path + date_util.get_now_day_str() + '/'
            if os.path.exists(report_path) is False:
                os.makedirs(report_path)
            for task in all_list:
                try:
                    banner_path = dict()
                    ztag_path = dict()
                    banner_list = models.BannerTask.objects.filter(scan_task_id=task.id, execute_status=2).all()
                    for info in banner_list:
                        if info.banner_result_path is not None:
                            banner_path[info.banner_result_path] = "banner_"+info.protocol+".json"
                        if info.ztag_result_path is not None:
                            ztag_path[info.ztag_result_path] = "ztag_"+info.protocol+".json"

                    filename = str(task.id) + '_' + str(task.port) + '.tar.gz'
                    file_path = report_path + filename
                    with tarfile.open(file_path, 'w:gz') as tar:
                        tar.add(task.port_result_path, arcname='zmap.csv')
                        for msg in banner_path.keys():
                            tar.add(msg, arcname=banner_path.get(msg))
                        for msg in ztag_path.keys():
                            tar.add(msg, arcname=ztag_path.get(msg))
                    file_md5 = file_hash(file_path)
                    models.ScanTask.objects.filter(id=task.id).update(report_result_path=file_path, report_file_md5=file_md5, upload_status=0)
                    os.remove(task.port_result_path)
                    for msg in banner_path.keys():
                        os.remove(msg)
                    for msg in ztag_path.keys():
                        os.remove(msg)
                except BaseException as e2:
                    print(e2, task)
        time.sleep(delay)


def get_mac():
    address = hex(uuid.getnode())[2:]
    address = address.upper()
    return '-'.join(address[i:i + 2] for i in range(0, len(address), 2))


def upload_center(delay):
    while True:
        scan_finish_list = models.ScanTask.objects.filter(upload_status=0).all()
        if len(scan_finish_list) > 0:
            for up in scan_finish_list:
                try:
                    data = {
                        'port': up.port,
                        'count': up.ip_count,
                        'ip_range': up.ip_range,
                        'client_ip': get_mac(),
                        'time': up.finish_time.time()
                    }

                    report_file = open(up.report_result_path, "rb")

                    files = {
                        'file': report_file
                    }

                    response = requests.post('https://182.148.53.139:18081/dataExchange/upload4scan', data=data, files=files, verify=False)
                    if response.json()['msg'] == 'success':
                        models.ScanTask.objects.filter(id=up.id).update(upload_status=1)
                        os.remove(up.report_result_path)
                except BaseException as e:
                    print(up, e)

        time.sleep(delay)


# thread.start_new_thread(upload_center, (2,))

# thread.start_new_thread(zmap_start, (2,))
# thread.start_new_thread(exec_banner_job, (2,))
# thread.start_new_thread(exec_finish_job, (2,))


# print(timezone.now())
