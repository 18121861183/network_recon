import _thread
import hashlib
import io
import json
import os
import subprocess
import tarfile
import threading
import time
import uuid
import logging

import paramiko as paramiko
import urllib3

from django.shortcuts import render

# Create your views here.
from django.utils import timezone
from pykafka import KafkaClient

from network_recon import settings
from recon import models, date_util, hash_util, generation_task
from recon.common import port_protocols, unfinished, ztag_command
from util import split_tar_report

urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S',
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s')

try:
    models.ScanTask.objects.filter(execute_status=1).update(execute_status=0)
    models.BannerTask.objects.filter(execute_status=1).update(execute_status=0)
except BaseException as e:
    print(e)


def index(request):
    return render(request, "index.html")


def zmap_start(delay):
    while True:
        number = models.BannerTask.objects.filter(execute_status=0).count()
        if number > 0:
            time.sleep(delay)
            continue
        task = models.ScanTask.objects.filter(execute_status=0, priority__gt=1).order_by('priority').order_by('issue_time').first()
        if task is not None:
            logging.info("check out task for waiting " + task.__str__())
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
    logging.info("start online running command: "+command)

    try:
        # subprocess.call(command, shell=True)
        ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if len(ret.stderr) > 0:
            logging.error("error run online command: "+str(ret.stderr))
            # return
        logging.info("online finish command: "+str(command))
        count = 0
        with open(task_info.port_result_path, "r") as file:
            for _ in file.readlines():
                count += 1

        port = task_info.port
        protocol_str = task_info.protocol
        if len(protocol_str) > 0:
            protocols = protocol_str.split(",")
        else:
            protocols = port_protocols.get(port)
        task_number = 0
        logging.info("start generator banner task: " + str(task_info.id))
        for protocol in protocols:
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
                                             ip_count=count, scan_task_id=task_info.id,
                                             banner_result_path=zgrab_result_path,
                                             ztag_result_path=ztag_result_path, ztag_status=ztag_status,
                                             priority=task_info.priority, create_time=timezone.now())
            task_number += 1

        logging.info("generator banner task numbers: "+str(task_number))

        models.ScanTask.objects.filter(id=task_info.id).update(execute_status=2, open_port_count=count,
                                                               banner_task_count=task_number)

        logging.info("record running task log: " + str(count))
        models.ReconRecordLog.objects.create(id=uuid.uuid1(), ip_count=task_info.ip_count,
                                             command=command, success_count=count,
                                             task_type="online", create_time=timezone.now())
    except BaseException as e1:
        logging.error("zmap scan error: "+str(e1)+" | "+command)
        models.ScanTask.objects.filter(id=task_info.id).update(execute_status=-1)


def exec_banner_job(delay):
    while True:
        logging.info("checked unfinished banner task...")
        task_info = models.BannerTask.objects.filter(execute_status=0).order_by('priority').order_by('create_time').first()
        if task_info is not None:
            models.BannerTask.objects.filter(id=task_info.id).update(execute_status=1)
            banner_start(task_info)
        time.sleep(delay)


def banner_start(task_info):
    command = task_info.command
    logging.info("start banner task: " + command)
    try:
        # subprocess.call(command, shell=True)
        ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if len(ret.stderr) > 0:
            logging.error("error run banner command:"+str(ret.stderr))
        logging.info("finish banner task:"+command)
        count = 0
        with open(task_info.banner_result_path, "r") as file:
            for line in file.readlines():
                if line.find('"error":"') == -1:
                    count += 1

        banner_size = os.path.getsize(task_info.banner_result_path)
        records_handled = 0
        ztag_status = -1
        ztag_size = 0
        if task_info.ztag_status == 0:
            ztag_status = 0
            shell_command = 'cat ' + task_info.banner_result_path + ' | ztag -p ' + str(task_info.port) + ' ' \
                            + ztag_command.get(task_info.protocol) + ' > ' + task_info.ztag_result_path
            output = subprocess.getoutput(shell_command)
            print("ztag result", output)
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
            ztag_size = os.path.getsize(task_info.banner_result_path)

        models.BannerTask.objects.filter(id=task_info.id).update(execute_status=2, banner_success_count=count, banner_size=banner_size,
                                                                 ztag_handle_count=records_handled, ztag_size=ztag_size,
                                                                 ztag_status=ztag_status, finish_time=timezone.now())
        scantask = models.ScanTask.objects.filter(id=task_info.scan_task_id).first()
        if scantask is not None:
            logging.info("start deal scan task numbers:"+str(scantask.banner_task_count))
            number = scantask.banner_task_count - 1
            if number == 0:
                models.ScanTask.objects.filter(id=task_info.scan_task_id).update(banner_task_count=number, finish_time=timezone.now())
            else:
                models.ScanTask.objects.filter(id=task_info.scan_task_id).update(banner_task_count=number)
            models.ReconRecordLog.objects.create(id=uuid.uuid1(), ip_count=task_info.ip_count,
                                                 command=command, success_count=count,
                                                 task_type="banner", create_time=timezone.now())
        else:
            logging.error("error data in database task:"+command)
    except BaseException as e1:
        logging.error("zgrab scan error:" + str(e1) + " | "+task_info.command)
        models.BannerTask.objects.filter(id=task_info.id).update(execute_status=-1)


def exec_finish_job(delay):
    while True:
        logging.info("check finish task...")
        all_list = models.ScanTask.objects.filter(execute_status=2).filter(banner_task_count=0)\
                                          .filter(upload_status=-1).order_by('priority').order_by('issue_time').all()
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
                            banner_path[info.banner_result_path] = "banner_"+info.protocol+"_"+str(info.port)+".json"
                        if info.ztag_result_path is not None:
                            ztag_path[info.ztag_result_path] = "ztag_"+info.protocol+"_"+str(info.port)+".json"

                    filename = str(task.id) + '_' + str(task.port) + '.tar.gz'
                    file_path = report_path + filename
                    params = {
                        'port': task.port,
                        'count': task.ip_count,
                        'ip_range': task.ip_range,
                        'client_ip': get_mac(),
                        'protocols': task.protocol,
                        'time': task.finish_time.time()
                    }
                    # 添加探测参数文件到压缩包
                    _file = open(settings.temp_file_path+"/param.json", "w")
                    _file.write(json.dumps(params))
                    _file.close()
                    with tarfile.open(file_path, 'w:gz') as tar:
                        tar.add(task.port_result_path, arcname='zmap'+"_"+str(task.port)+'.csv')
                        tar.add(settings.temp_file_path+"/param.json", arcname='param.json')
                        for msg in banner_path.keys():
                            tar.add(msg, arcname=banner_path.get(msg))
                        for msg in ztag_path.keys():
                            tar.add(msg, arcname=ztag_path.get(msg))
                    file_md5 = file_hash(file_path)
                    report_size = os.path.getsize(file_path)
                    models.ScanTask.objects.filter(id=task.id).update(report_result_path=file_path, report_file_md5=file_md5,
                                                                      report_size=report_size, upload_status=0)
                    if len(banner_path.keys()) > 0:
                        logging.info("delete report sub child files, all in report... path in:"+report_path)
                        os.remove(task.port_result_path)
                        for msg in banner_path.keys():
                            os.remove(msg)
                        for msg in ztag_path.keys():
                            os.remove(msg)
                except BaseException as e2:
                    logging.error("generation report error: "+str(e2)+" | "+task.command)
        time.sleep(delay)


def get_mac():
    address = hex(uuid.getnode())[2:]
    address = address.upper()
    return '-'.join(address[i:i + 2] for i in range(0, len(address), 2))


def sftp_upload(local):
    sf = paramiko.Transport((settings.sftp_host, settings.sftp_port))
    sf.connect(username=settings.sftp_username, password=settings.sftp_password)
    sftp = paramiko.SFTPClient.from_transport(sf)
    reports = split_tar_report.split_file(path=local)
    for send in reports:
        filename = str(send).rsplit("/", 1)[1]
        try:
            sftp.put(send, settings.sftp_remote+filename)
        except:
            sftp.put(send, settings.sftp_remote + filename)
    sf.close()


def upload_center(delay):
    while True:
        logging.info("now running upload center...")
        scan_finish_list = models.ScanTask.objects.filter(upload_status=0).all()
        if len(scan_finish_list) > 0:
            for up in scan_finish_list:
                try:
                    sftp_upload(up.report_result_path)
                    models.ScanTask.objects.filter(id=up.id).update(upload_status=1)
                except BaseException as e2:
                    logging.error("upload center error", up, e2)

        time.sleep(delay)


def real_time_scan():
    while True:
        task = models.ScanTask.objects.filter(execute_status=0, priority=1).order_by('issue_time').first()
        if task is not None:
            logging.info("check out task for waiting " + task.__str__())
            models.ScanTask.objects.filter(id=task.id).update(execute_status=1)
            scan_start(task)
        time.sleep(1)


# _thread.start_new_thread(upload_center, (2,))
#
# _thread.start_new_thread(zmap_start, (2,))
# _thread.start_new_thread(exec_banner_job, (2,))
# _thread.start_new_thread(exec_finish_job, (2,))
# 实时探测任务
# _thread.start_new_thread(real_time_scan, (2,))

# print(timezone.now())


"""
kafka接收要探测的数据
接收数据并入数据库
"""


# kafka连接获取数据
# def start_fast_recon():
#     client = KafkaClient(hosts=settings.kafka_host)
#     topic = client.topics[settings.kafka_topics_prior]
#     consumer = topic.get_simple_consumer(consumer_group=b'first', auto_commit_enable=True, auto_commit_interval_ms=1, consumer_id=b'prior')
#     for message in consumer:
#         logging.info("receive fast recon ips: " + str(message.value))
#         if len(message.value) > 2:
#             ip_addr = json.loads(message.value).get("ip", "")
#             if ip_addr != "" and models.ReceiveScans.objects.filter(ip=ip_addr).count() == 0:
#                 models.ReceiveScans.objects.create(ip=ip_addr, status=0, flag=1).save()
#
#
# def start_normal_rec():
#     client = KafkaClient(hosts=settings.kafka_host)
#     topic = client.topics[settings.kafka_topics_normal]
#     consumer = topic.get_simple_consumer(consumer_group=b'latter', auto_commit_enable=True, auto_commit_interval_ms=1, consumer_id=b'normal')
#     for message in consumer:
#         logging.info("receive normal recon ips: " + str(message.value))
#         if len(message.value) > 2:
#             ip_addr = json.loads(message.value).get("ip", "")
#             if ip_addr != "" and models.ReceiveScans.objects.filter(ip=ip_addr).count() == 0:
#                 models.ReceiveScans.objects.create(ip=ip_addr).save()


# _thread.start_new_thread(start_fast_recon, ())
# _thread.start_new_thread(start_normal_rec, ())
# t1 = threading.Thread(target=start_fast_recon, name='worker1')  # 线程对象.
# t1.start()
# t2 = threading.Thread(target=start_normal_rec, name='worker2')  # 线程对象.
# t2.start()


"""
定时生产执行任务:
    即时探测任务生成
    批量探测任务生成
"""


# 快速扫描任务生成
def check_scan_ips(delay):
    while True:
        logging.debug("running generation task...")
        try:
            number = models.ReceiveScans.objects.filter(flag=1, status=0).count()
            if number > 0:
                models.ReceiveScans.objects.filter(flag=1, status=0).update(status=1)
                deal = models.ReceiveScans.objects.filter(flag=1, status=1).all()
                filename = str(date_util.get_now_timestamp())+".txt"
                file_path = settings.scan_file_path+filename
                _file = open(file_path, "w")
                for line in deal:
                    print(line.ip)
                    _file.write(line.ip+"\n")
                _file.close()
                # 生成任务指令
                generation_task.generation(file_path)
                models.ReceiveScans.objects.filter(flag=1, status=1).update(status=2)
        except BaseException as be:
            logging.error("gen task error: "+str(be))
        time.sleep(delay)


# 每日一次批量探测
def batch_scan():
    logging.info("timer start result....")
    try:
        number = models.ReceiveScans.objects.filter(flag=0, status=0).count()
        if number > 0:
            models.ReceiveScans.objects.filter(flag=0, status=0).update(status=1)
            deal = models.ReceiveScans.objects.filter(flag=0, status=1).all()
            filename = str(date_util.get_now_timestamp()) + ".txt"
            file_path = settings.scan_file_path + filename
            _file = open(file_path, "w")
            for line in deal:
                print(line.ip)
                _file.write(line.ip + "\n")
            _file.close()
            # 生成任务指令
            generation_task.generation_normal(file_path)
            models.ReceiveScans.objects.filter(flag=0, status=1).update(status=2)
    except BaseException as be:
        logging.error("gen task error: " + str(be))


_thread.start_new_thread(check_scan_ips, (1,))



