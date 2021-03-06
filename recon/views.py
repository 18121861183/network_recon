import _thread
import csv
import hashlib
import io
import json
import os
import subprocess
import tarfile
import time
import uuid
import logging

# import paramiko as paramiko
import requests
import urllib3
from collections import Counter
from django.db.models import F
from django.http import HttpResponse

from django.shortcuts import render

# Create your views here.
from django.utils import timezone

from network_recon import settings
from recon import models, date_util, hash_util, generation_task
from recon.common import unfinished
# from util import split_tar_report
from recon.private_dict import BigDict

urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S',
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s')

try:
    models.ScanTask.objects.filter(execute_status=1).update(execute_status=0)
    models.BannerTask.objects.filter(execute_status=1).update(execute_status=0)
except BaseException as e:
    print(e)


'''
zmap_result_path = '/opt/recon/zmap/'
banner_save_path = '/opt/recon/zgrab/'
report_save_path = '/opt/recon/report/'
zmap_white_path = '/opt/recon/scan/'
temp_file_path = '/opt/recon/temp/'
scan_file_path = '/opt/recon/fasts/'
'''
if os.path.exists(settings.zmap_result_path) is False:
    os.makedirs(settings.zmap_result_path)


if os.path.exists(settings.banner_save_path) is False:
    os.makedirs(settings.banner_save_path)


if os.path.exists(settings.report_save_path) is False:
    os.makedirs(settings.report_save_path)


if os.path.exists(settings.zmap_white_path) is False:
    os.makedirs(settings.zmap_white_path)


if os.path.exists(settings.temp_file_path) is False:
    os.makedirs(settings.temp_file_path)


if os.path.exists(settings.scan_file_path) is False:
    os.makedirs(settings.scan_file_path)


if os.path.exists(settings.scan_task_summary) is False:
    os.makedirs(settings.scan_task_summary)


def index(request):
    return render(request, "index.html")


def init(request):
    flag = request.GET.get("check", "")
    if flag == "" or flag != "circulate_init":
        return HttpResponse(json.dumps({"msg": "无效请求!请确认URL是否正确!"}))
    circulate_number = models.ScanTask.objects.first().circulate_number + 1
    models.ScanTask.objects.update(open_port_count=0, finish_time=None, report_result_path=None,
                                   report_file_md5=None, report_size=0, execute_status=0, send_banner_task=0,
                                   banner_task_count=-1, upload_status=-1, circulate_number=circulate_number)
    models.BannerTask.objects.all().delete()
    models.ReceiveScans.objects.all().delete()
    run_list = ["rm -f "+settings.zmap_result_path+"*", "rm -f "+settings.banner_save_path+"*",
                "rm -f "+settings.scan_file_path+"*", "rm -rf "+settings.report_save_path + "*"]
    for command in run_list:
        subprocess.run(command, shell=True)
    return HttpResponse(json.dumps({"msg": "初始化完成!"}))


def zmap_start(delay):
    while True:
        number = models.BannerTask.objects.filter(execute_status=0).count()
        if number > 0:
            time.sleep(delay)
            continue
        task = models.ScanTask.objects.filter(execute_status=0, priority__gt=0).order_by('priority', "issue_time").first()
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

        pt = task_info.port
        ports = str(pt).split(",")
        protocol_str = task_info.protocol
        if len(protocol_str) > 0:
            protocols = protocol_str.split(",")
        else:
            protocols = []
        task_number = 0
        logging.info("start generator banner task: " + str(task_info.id))
        for port in ports:
            for protocol in protocols:
                if protocol in unfinished:
                    continue
                banner_command = ["zgrab2", "-f", task_info.port_result_path, protocol, "-p", str(port), "-t 5s"]
                _id = hash_util.get_md5(" ".join(banner_command))
                zgrab_result_path = settings.banner_save_path + protocol + "_" + str(port) + "_" + _id + ".json"
                banner_command.append('--output-file='+zgrab_result_path)
                models.BannerTask.objects.create(id=_id, command=" ".join(banner_command), port=port, protocol=protocol,
                                                 ip_count=count, scan_task_id=task_info.id,
                                                 banner_result_path=zgrab_result_path,
                                                 priority=task_info.priority, create_time=timezone.now())
                task_number += 1

        logging.info("generator banner task numbers: "+str(task_number))

        models.ScanTask.objects.filter(id=task_info.id).update(execute_status=2, open_port_count=count,
                                                               banner_task_count=task_number)
        # 更新完成任务数量
        parent = models.GeneralScanTask.objects.filter(id=task_info.parent_id).first()
        finish_count = parent.finished_sub_task_count + 1
        models.GeneralScanTask.objects.filter(id=task_info.parent_id).update(finished_sub_task_count=finish_count)
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

        models.BannerTask.objects.filter(id=task_info.id).update(execute_status=2, banner_success_count=count,
                                                                 banner_size=banner_size, finish_time=timezone.now())
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
            # 更新完成任务数量
            parent = models.GeneralScanTask.objects.filter(id=scantask.parent_id).first()
            finish_count = parent.finished_sub_task_count + 1
            if finish_count == parent.all_sub_task_count:
                models.GeneralScanTask.objects.filter(id=scantask.parent_id).update(finished_sub_task_count=finish_count, execute_status=2)
            else:
                models.GeneralScanTask.objects.filter(id=scantask.parent_id).update(finished_sub_task_count=finish_count)
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
                    summary_sub_save = settings.scan_task_summary + task.parent_id + "/"
                    if os.path.exists(summary_sub_save) is False:
                        os.makedirs(summary_sub_save)

                    csv_file = open(summary_sub_save+task.id+".csv", 'w', newline='')
                    row_writer = csv.writer(csv_file, quotechar=',', quoting=csv.QUOTE_MINIMAL)

                    banner_list = models.BannerTask.objects.filter(scan_task_id=task.id, execute_status=2).all()
                    for info in banner_list:
                        if info.banner_result_path is not None:
                            banner_path[info.banner_result_path] = "banner_"+info.protocol+"_"+str(info.port)+".json"
                            # 处理详细数据统计
                            with open(info.banner_result_path, "r+") as ban:
                                for line in ban:
                                    if line.find('"status":"success"') > -1:
                                        try:
                                            obj = json.loads(line.strip())
                                            row_writer.writerow([obj['ip'], info.protocol, info.port])
                                        except BaseException as ee:
                                            print(ee)

                    filename = str(task.id) + '_' + str(task.port) + '.tar.gz'
                    file_path = report_path + filename
                    params = {
                        'port': task.port,
                        'count': task.ip_count,
                        'ip_range': task.ip_range,
                        'client_ip': get_mac(),
                        'protocols': task.protocol,
                        'time': str(task.finish_time.timestamp())
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
                    file_md5 = file_hash(file_path)
                    report_size = os.path.getsize(file_path)
                    models.ScanTask.objects.filter(id=task.id).update(report_result_path=file_path, report_file_md5=file_md5,
                                                                      report_size=report_size, upload_status=0)

                    if len(banner_path.keys()) > 0:
                        logging.info("delete report sub child files, all in report... path in:"+report_path)
                        os.remove(task.port_result_path)
                        for msg in banner_path.keys():
                            os.remove(msg)
                except BaseException as e2:
                    logging.error("generation report error: "+str(e2)+" | "+task.command)
        time.sleep(delay)


def get_mac():
    address = hex(uuid.getnode())[2:]
    address = address.upper()
    return '-'.join(address[i:i + 2] for i in range(0, len(address), 2))


def dict_to_jsons(detail_list):
    new_list = list()
    for key in detail_list.keys():
        info = dict()
        info["ip"] = key
        info["value"] = detail_list.get(key)
        new_list.append(info)
    return new_list


def gene_summary_file(total, online, ip_tops, protocol_tops, port_tops, detail_list, save_to_file):
    summary = dict()
    summary["total"] = total
    summary["online"] = online
    ip_top = dict()
    for ip in ip_tops:
        ip_top[ip[0]] = ip[1]
    summary["ip_top"] = ip_top
    protocol_top = dict()
    for protocol in protocol_tops:
        protocol_top[protocol[0]] = protocol_top[1]
    summary["protocol_top"] = protocol_top
    port_top = dict()
    for port in port_tops:
        port_top[port[0]] = port[1]
    summary["port_top"] = port_top
    summary["detail"] = dict_to_jsons(detail_list)
    file = open(save_to_file, "w")
    file.write(json.dumps(summary))
    file.close()


def start_deal(path, task):
    total = task.ip_count
    dirs = os.listdir(path)
    ip_list = list()
    protocol_list = list()
    port_list = list()
    detail_list = BigDict()
    for file_name in dirs:
        if file_name.endswith(".csv"):
            with open(path+"/"+file_name, newline='') as csv_file:
                reader = csv.reader(csv_file, quotechar=',')
                for row in reader:
                    detail_list.put(row[0], row[2]+"/"+row[1])
                    ip_list.__add__(row[0])
                    protocol_list.__add__(row[1])
                    port_list.__add__(row[2])
    # ip端口开放top10
    ip_counts = Counter(ip_list)
    ip_tops = ip_counts.most_common(10)

    # 协议top10
    protocol_counts = Counter(protocol_list)
    protocol_tops = protocol_counts.most_common(10)

    # 端口top10
    port_counts = Counter(port_list)
    port_tops = port_counts.most_common(10)

    # 统计在线ip
    online = len(set(ip_list))

    result_summary_path = settings.scan_task_summary + task.id + ".json"
    gene_summary_file(total, online, ip_tops, protocol_tops, port_tops, detail_list, result_summary_path)
    models.GeneralScanTask.objects.filter(id=task.id).update(summary_result_path=result_summary_path)
    logging.info("任务执行情况概要报告执行完成..." + task.id)


def exec_task_summary(delay):
    while True:
        logging.info("start task summary generation...")
        finished_list = models.GeneralScanTask.objects.raw("select * from recon_generalscantask where all_sub_task_count=finished_sub_task_count and summary_result_path is null")
        if len(finished_list) > 0:
            for finish in finished_list:
                current_path = settings.scan_task_summary+finish.id
                logging.info("开始处理任务概要情况生成：..." + finish.id)
                start_deal(current_path, finish)
        time.sleep(delay)


# def sftp_upload(local):
#     sf = paramiko.Transport((settings.sftp_host, settings.sftp_port))
#     sf.connect(username=settings.sftp_username, password=settings.sftp_password)
#     sftp = paramiko.SFTPClient.from_transport(sf)
#     reports = split_tar_report.split_file(path=local)
#     for send in reports:
#         filename = str(send).rsplit("/", 1)[1]
#         try:
#             sftp.put(send, settings.sftp_remote+filename)
#         except:
#             sftp.put(send, settings.sftp_remote + filename)
#     sf.close()


def upload_center(delay):
    while True:
        logging.info("now running upload center...")
        scan_finish_list = models.ScanTask.objects.filter(upload_status=0).all()
        if len(scan_finish_list) > 0:
            for up in scan_finish_list:
                try:
                    # sftp_upload(up.report_result_path)
                    # models.ScanTask.objects.filter(id=up.id).update(upload_status=1)
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

                    response = requests.post(settings.center_url, data=data,
                                             files=files, verify=False)
                    logging.warning("upload center result: " + response.text)
                    if response.json()['msg'] == 'success':
                        models.ScanTask.objects.filter(id=up.id).update(upload_status=1)
                        # os.remove(up.report_result_path)
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


_thread.start_new_thread(zmap_start, (2,))
_thread.start_new_thread(exec_banner_job, (2,))
_thread.start_new_thread(exec_finish_job, (2,))
_thread.start_new_thread(upload_center, (2,))
_thread.start_new_thread(exec_task_summary, (2,))

# 实时探测任务
# _thread.start_new_thread(real_time_scan, ())

# print(timezone.now())


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



