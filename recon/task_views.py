import _thread
import datetime
import ipaddress
import json
import os

from django.core import serializers
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.http import JsonResponse
from django.utils import timezone

from network_recon import settings
from recon import models, common, hash_util
from recon.common import protocol_ports
from recon.hash_util import get_sha1


def generate_task(request):
    """
    探测任务生成
    :param request:
    :return:
    """
    if request.method == 'POST':
        scan_type = request.POST.get("scan_type")
        if scan_type not in ["normal", "deep"]:
            return JsonResponse('{"msg", "非法请求!"}', safe=False)
        ip_list = request.POST.get("ip_list")
        if len(ip_list) == 0:
            return JsonResponse('{"msg", "缺少必要的参数!"}', safe=False)
        exclude_list = request.POST.get("exclude_list", "")
        pps = request.POST.get("pps", 666)
        scan_method = request.POST.get("scan_method", "telnet")
        if scan_method not in ["telnet", "ping", "socket"]:
            return JsonResponse('{"msg", "错误的扫描方式!"}', safe=False)
        protocols = request.POST.get("protocols")
        ports = request.POST.get("ports")
        ports_list = list()
        if scan_type == "normal":
            # 常规配置扫描
            if len(protocols) == 0 or len(ports) == 0:
                return JsonResponse('{"msg", "缺少必要的参数!"}', safe=False)
            ports_list = str(ports).split(",")
        elif scan_type == "deep":
            protocols = format_list(protocol_ports.keys())
            ports = "1-65535"
            ports_list = range(1, 65536)
        username = request.POST.get("username")
        # 处理扫描任务IP列表

        general_id = get_sha1(username + scan_type + scan_method + pps + protocols + ip_list + exclude_list)
        if models.GeneralScanTask.objects.filter(id=general_id):
            return JsonResponse('{"msg", "任务已存在!"}', safe=False)
        all_path = generate_scan_file(ip_list, exclude_list)
        ip_count = 0
        for path in all_path:
            ip_count += ip_number(path)
        all_task = len(ports_list)*len(protocols.split(","))
        if scan_method != "socket":
            all_task += len(ports_list)
        models.GeneralScanTask.objects.create(id=general_id, scan_type=scan_type, scan_method=scan_method,
                                              ip_list=ip_list, port=ports, protocol=protocols, scan_speed=pps,
                                              exclude_list=exclude_list, issue_time=timezone.now(), ip_count=ip_count,
                                              username=username, execute_status=0, all_sub_task_count=all_task).save()
        _thread.start_new_thread(generate_execute, (scan_method, pps, protocols, ports_list, general_id, all_path))
        return JsonResponse('{"msg", "success"}', safe=False)
    else:
        return JsonResponse('{"msg", "请使用POST方法!"}', safe=False)


def format_list(array):
    string = ""
    for ar in array:
        if len(string) > 0:
            string += ","
        string += ar
    return string


def deal_scan_ip(ips_list, ext_list):
    path_list = []
    result = set()
    to_single_ip(ips_list, result)
    to_single_ip(ext_list, result)
    count = 0
    file_number = 1
    file_name = datetime.datetime.now().strftime("%Y%m%d%H%M%S_")
    first_path = settings.zmap_white_path + file_name + str(file_number)
    _outfile = open(first_path, 'w')
    if len(result) > 0:
        path_list.append(first_path)
        for ip in result:
            if count != 0 and count > settings.record_max_ips:
                _outfile.close()
                file_number += 1
                count = 0
                _outfile = open(settings.zmap_white_path + file_name + str(file_number), 'w')
                path_list.append(settings.zmap_white_path + file_name + str(file_number))
            line = ip.strip()
            _outfile.write(line + "\n")
            count += 1
    return path_list


def to_single_ip(ips_list, result):
    for ips in ips_list:
        if str(ips).find("-") > 0:
            array = ips.split("-")
            if len(array) != 2:
                raise Exception("ip地址队列存在非法的格式!")
            for ip_num in range(int(ipaddress.IPv4Address(array[0])), int(ipaddress.IPv4Address(array[1])) + 1):
                result.add(str(ipaddress.ip_address(int(ip_num))))
        elif str(ips).find("/") > 0:
            for ip in list(ipaddress.ip_network(ips, False).hosts()):
                result.add(str(ip))
        else:
            result.add(ips.strip())


def generate_scan_file(ips, excludes):
    ips_list = ips.split(",")
    if excludes is None or excludes == "":
        ext_list = []
    else:
        ext_list = excludes.split(",")
    return deal_scan_ip(ips_list, ext_list)


def ip_number(file):
    number = 0
    with open(file, 'r') as ips:
        for _ in ips.readlines():
            number += 1
    return number


def path_get_filename(path):
    if path is not None and str(path).find("/") > -1:
        array = path.split("/")
        return array[len(array)-1]


def cron_generate_execute():
    general_task_list = models.GeneralScanTask.objects.filter(execute_status=0).all()
    for general_task in general_task_list:
        print(general_task.id)


def generate_execute(scan_method, pps, protocols, ports, parent_id, all_path):
    execute_status = 0
    if scan_method == "socket":
        execute_status = 2
    protocol_list = protocols.split(",")
    for path in all_path:
        number = ip_number(path)
        if number == 0:
            continue
        # ping扫不依赖端口如何处理??
        if scan_method == "telnet" or scan_method == "socket":
            for port in ports:
                file1 = path + "_" + str(port)
                command = ['zmap', '-w', path, '-r', pps, '-p', str(port), ' | ztee', file1]
                command_str = " ".join(command)
                _id = get_sha1(command_str)
                banner_task_count = -1
                if scan_method == "socket":
                    banner_task_count = len(protocol_list)
                models.ScanTask.objects.create(id=_id, parent_id=parent_id, command=command_str, port=port,
                                               protocol=protocols, ip_range="*", ip_count=number, port_result_path=file1,
                                               issue_time=timezone.now(), execute_status=execute_status,
                                               banner_task_count=banner_task_count, priority=3).save()
                if scan_method == "socket":
                    for protocol in protocol_list:
                        if protocol in common.unfinished:
                            continue
                        banner_command = ["zgrab2", "-f", path, protocol, "-p", str(port), "-t 5s"]
                        banner_id = hash_util.get_md5(" ".join(banner_command))
                        zgrab_result_path = settings.banner_save_path + protocol + "_" + str(port) + "_" + banner_id + ".json"
                        banner_command.append('--output-file=' + zgrab_result_path)
                        models.BannerTask.objects.create(id=banner_id, command=" ".join(banner_command), port=port,
                                                         protocol=protocol, ip_count=number, scan_task_id=_id,
                                                         banner_result_path=zgrab_result_path,
                                                         priority=3, create_time=timezone.now())
        elif scan_method == "ping":
            file1 = settings.zmap_result_path + '_' + path_get_filename(path)
            command = ['zmap', '-w', path, '-r', pps, ' | ztee', file1]
            _id = get_sha1(" ".join(command))
            models.ScanTask.objects.create(id=_id, parent_id=parent_id, command=" ".join(command),
                                           port=format_list(ports), protocol=protocols, ip_range="*",
                                           ip_count=number, port_result_path=file1, issue_time=timezone.now(),
                                           execute_status=execute_status, priority=3).save()


def scan_task_query(request):
    page = request.POST.get("page", 1)
    size = request.POST.get("size", 10)
    status = request.POST.get("status", None)
    if status is None:
        pageData = models.GeneralScanTask.objects.filter(execute_status__in=[0, 1, 2, -1, 3, 4]).order_by("-issue_time").all()
        record_size = models.GeneralScanTask.objects.filter(execute_status__in=[0, 1, 2, -1, 3, 4]).order_by("-issue_time").all().count()
    else:
        status = status.split(',')
        pageData = models.GeneralScanTask.objects.filter(execute_status__in=status).order_by("-issue_time").all()
        record_size = models.GeneralScanTask.objects.filter(execute_status__in=status).order_by("-issue_time").all().count()
    if pageData:
        paginator = Paginator(pageData, size)
        try:
            contacts = paginator.page(page)
        except PageNotAnInteger:
            # 如果用户请求的页码号不是整数，显示第一页
            contacts = paginator.page(1)
        except EmptyPage:
            # 如果用户请求的页码号超过了最大页码号，显示最后一页
            contacts = paginator.page(paginator.num_pages)
        # for task in contacts.object_list:
        #     task_process(task)
        page_list = serializers.serialize("json", contacts)
        result = json.loads(page_list, encoding='utf-8')

        return JsonResponse({"record_list": result, "record_size": record_size}, charset='utf-8', safe=False)
    return JsonResponse('[]', safe=False)


def task_detail(request):
    _id = request.POST.__getitem__("id")
    mainTask = models.GeneralScanTask.objects.filter(id=_id)
    sub_task_list = models.ScanTask.objects.filter(parent_id=_id).all()
    all_sub_task_count = sub_task_list.count()
    finished_sub_task_count = 0
    for sub_task in sub_task_list:
        if sub_task.execute_status == 2 and sub_task.upload_status == 1:
            finished_sub_task_count += 1
    if finished_sub_task_count == all_sub_task_count:
        models.GeneralScanTask.objects.filter(id=_id).update(execute_status=2)
    mainInfo = serializers.serialize("json", mainTask)
    mainResult = json.loads(mainInfo, encoding='utf-8')
    subResult = {"all_sub_task_count": all_sub_task_count, "finished_sub_task_count": finished_sub_task_count}
    return JsonResponse({"main": mainResult, "sub": subResult}, charset="utf-8")


def delete_file(paths):
    for path in paths:
        if path is None:
            continue
        if len(path) > 0:
            os.remove(path)


def task_operation(request):
    _id = request.POST.__getitem__("id")
    ope = request.POST.__getitem__("operation")
    if ope is None or ope not in ["start", "stop", "delete", "cancel"]:
        return JsonResponse('{"msg", "缺少必要的参数!"}', safe=False)
    general_scan_task = models.GeneralScanTask.objects.get(id=_id)
    if ope == 'start':
        # 如果任务为暂停状态,启动所有未完成子任务
        if general_scan_task.execute_status == 3:
            scan_task_list = models.ScanTask.objects.filter(parent_id=_id, execute_status=3).all()
            for scan_task in scan_task_list:
                scan_task_id = scan_task.id
                if scan_task.execute_status == 3:
                    models.BannerTask.objects.filter(scan_task_id=scan_task_id, execute_status=3).update(execute_status=0)
                    scan_task.execute_status = 1
                    scan_task.save()
            general_scan_task.execute_status = 1
            general_scan_task.save()
        # 如果任务为终止状态,启动所有子任务
        elif general_scan_task.execute_status == 4:
            scan_task_list = models.ScanTask.objects.filter(parent_id=_id).all()
            for scan_task in scan_task_list:
                scan_task_id = scan_task.id
                models.BannerTask.objects.filter(scan_task_id=scan_task_id).update(execute_status=0)
                scan_task.execute_status = 1
                scan_task.upload_status = -1
                scan_task.save()
            general_scan_task.execute_status = 1
            general_scan_task.save()
    elif ope == 'stop':
        general_scan_task.execute_status = 3
        general_scan_task.save()
        scan_task_list = models.ScanTask.objects.filter(parent_id=_id).all()
        for scan_task in scan_task_list:
            scan_task_id = scan_task.id
            models.BannerTask.objects.filter(scan_task_id=scan_task_id, execute_status=0).update(execute_status=3)
            models.BannerTask.objects.filter(scan_task_id=scan_task_id, execute_status=1).update(execute_status=3)
            if scan_task.execute_status != 2:
                scan_task.execute_status = 3
                scan_task.save()
    elif ope == 'delete':
        general_scan_task.execute_status = 5
        general_scan_task.save()
        scan_task_list = models.ScanTask.objects.filter(parent_id=_id).all()
        for scan_task in scan_task_list:
            scan_task_id = scan_task.id
            paths = []
            if scan_task.port_result_path is not None:
                paths.append(scan_task.port_result_path)
            if scan_task.report_result_path is not None:
                paths.append(scan_task.report_result_path)
            results = models.BannerTask.objects.filter(scan_task_id=scan_task_id, execute_status=2).all()
            for banner in results:
                if banner.banner_result_path is not None:
                    paths.append(banner.banner_result_path)
            models.BannerTask.objects.filter(scan_task_id=scan_task_id).delete()
            models.ScanTask.objects.filter(id=scan_task_id).delete()
            delete_file(paths)
    elif ope == 'cancel':
        general_scan_task.execute_status = 4
        general_scan_task.save()
        scan_task_list = models.ScanTask.objects.filter(parent_id=_id).all()
        for scan_task in scan_task_list:
            scan_task_id = scan_task.id
            if scan_task.execute_status != 2:
                models.BannerTask.objects.filter(scan_task_id=scan_task_id, execute_status=0).update(execute_status=4)
                models.BannerTask.objects.filter(scan_task_id=scan_task_id, execute_status=1).update(execute_status=4)
                models.BannerTask.objects.filter(scan_task_id=scan_task_id, execute_status=3).update(execute_status=4)
                scan_task.execute_status = 4
                scan_task.save()
    return JsonResponse('{"msg": "success"}', safe=False)


# def task_process(task):
#     general_id = task.id
#     sub_task_list = models.ScanTask.objects.filter(parent_id=general_id).all()
#     all_sub_task_count = sub_task_list.count()
#     for task_info in sub_task_list:
#         all_sub_task_count += len(task_info.protocol.split(","))
#
#     finished_sub_task_count = 0
#     for sub_task in sub_task_list:
#         if sub_task.execute_status == 2 and (sub_task.upload_status == 1 or sub_task.upload_status == 0):
#             finished_sub_task_count += 1
#             finished_sub_task_count += len(sub_task.protocol.split(","))
#         elif sub_task.execute_status == 2 and sub_task.upload_status == -1:
#     finished_sub_task_count += models.BannerTask.objects.filter(scan_task_id=sub_task.id, execute_status=2).count()
#             finished_sub_task_count += 1
#     if all_sub_task_count == finished_sub_task_count:
#         task.execute_status = 2
#     task.all_sub_task_count = all_sub_task_count
#     task.finished_sub_task_count = finished_sub_task_count
#     task.save()


def get_protocols(request):
    return JsonResponse({"port_protocol": common.port_protocols, "protocol_port": common.protocol_ports})
