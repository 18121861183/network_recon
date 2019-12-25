import datetime
import ipaddress
import json
import os

from django.core import serializers
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.http import JsonResponse
from django.utils import timezone

from network_recon import settings
from recon import models, common
from recon.common import protocol_ports
from recon.hash_util import get_sha1


def generate_task(request):
    """
    探测任务生成
    :param request:
    :return:
    """
    main_type = request.GET.get("main_type", "")
    if main_type == "":
        main_type = request.POST.get("main_type", "")
    if main_type not in ["normal", "deep"]:
        return JsonResponse({"msg", "非法请求!"}, safe=False)
    ip_list = request.GET.get("ip_list", "")
    if ip_list == "":
        ip_list = request.POST.get("ip_list", "")
    if len(ip_list) == 0:
        return JsonResponse({"msg", "缺少必要的参数!"}, safe=False)
    exclude_list = request.GET.get("exclude_list")
    if exclude_list == "":
        exclude_list = request.POST.get("exclude_list")
    pps = request.GET.get("pps", 666)
    if pps == 666:
        pps = request.POST.get("pps", 666)
    scan_type = request.GET.get("scan_type", None)
    if scan_type is None:
        scan_type = request.POST.get("scan_type", "telnet")
    if scan_type not in ["telnet", "ping", "socket"]:
        return JsonResponse({"msg", "错误的扫描方式!"})
    protocols = request.GET.get("protocols", None)
    if protocols is None:
        protocols = request.POST.get("protocols", None)
    ports = request.GET.get("ports", None)
    if ports is None:
        ports = request.POST.get("ports", None)
    if main_type == "normal":
        # 常规配置扫描
        if len(protocols) == 0 or len(ports) == 0:
            return JsonResponse({"msg", "缺少必要的参数!"}, safe=False)
        ports = str(ports).split(",")
    elif main_type == "deep":
        protocols = format_list(protocol_ports.keys())
        ports = range(1-65536)
    # 处理扫描任务IP列表
    all_path = generate_scan_file(ip_list, exclude_list)
    generate_execute(all_path, scan_type, pps, protocols, ports)


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
    ext_list = excludes.split(",")
    return deal_scan_ip(ips_list, ext_list)


def ip_number(file):
    number = 0
    with open(file, 'r') as ips:
        for _ in ips.readlines():
            number += 1
    return number


def path_get_filename(path):
    if path is not None and str(path).find("/") > 0:
        array = path.split("/")
        return array[len(array)-1]


def generate_execute(all_path, scan_type, pps, protocols, ports):
    execute_status = 0
    if scan_type == "socket":
        execute_status = 2
    for path in all_path:
        number = ip_number(path)
        if number == 0:
            continue
        # ping扫不依赖端口如何处理??
        if scan_type == "telnet":
            for port in ports:
                file1 = path + "_" + str(port)
                command = ['zmap', '-w', path, '-r', pps, '-p', str(port), ' | ztee', file1]
                command_str = " ".join(command)
                _id = get_sha1(command_str)
                models.ScanTask.objects.create(id=_id, command=command_str, port=port, protocol=protocols, ip_range="*",
                                               ip_count=number, port_result_path=file1, issue_time=timezone.now(),
                                               execute_status=execute_status, priority=3).save()
        elif scan_type == "ping":
            file1 = settings.zmap_result_path + '_' + path_get_filename(path)
            command = ['zmap', '-w', path, '-r', pps, ' | ztee', file1]
            _id = get_sha1(" ".join(command))
            models.ScanTask.objects.create(id=_id, command=" ".join(command), port=format_list(ports),
                                           protocol=protocols, ip_range="*",
                                           ip_count=number, port_result_path=file1, issue_time=timezone.now(),
                                           execute_status=execute_status, priority=3).save()


def scan_task_query(request):
    page = request.GET.get("page", 1)
    size = request.GET.get("size", 10)
    status = request.GET.get("status", None)
    if status is None:
        pageData = models.ScanTask.objects.filter(execute_status__in=[0, 1, 2, -1, 4]).order_by("-issue_time").all()
    else:
        pageData = models.ScanTask.objects.filter(execute_status=status).order_by("-issue_time").all()
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
        for task in contacts.object_list:
            task_process(task)
        pageList = serializers.serialize("json", contacts)
        result = json.loads(pageList, encoding='utf-8')
        return JsonResponse(result, charset='utf-8')
    return JsonResponse([], safe=False)


def task_detail(request):
    _id = request.GET.get("id")
    mainTask = models.ScanTask.objects.filter(id=_id)
    subTask = models.BannerTask.objects.filter(scan_task_id=_id).all()
    mainInfo = serializers.serialize("json", mainTask)
    mainResult = json.loads(mainInfo, encoding='utf-8')
    subList = serializers.serialize("json", subTask)
    subResult = json.loads(subList, encoding='utf-8')
    return JsonResponse({"main": mainResult, "sub": subResult}, charset="utf-8")


def delete_file(paths):
    for path in paths:
        if len(path) > 0:
            os.remove(path)


def task_operation(request):
    _id = request.GET.get("id")
    ope = request.GET.get("operation")
    if ope is None or ope not in ["start", "stop", "delete", "cancel"]:
        return JsonResponse({"msg", "缺少必要的参数!"}, safe=False)
    scan_task = models.ScanTask.objects.get(id=_id)
    if ope == 'start':
        scan_task.task_flag = 'running'
        scan_task.save()
        if scan_task.execute_status == 2:
            models.BannerTask.objects.filter(scan_task_id=_id, execute_status=3).update(execute_status=0)
    elif ope == 'stop':
        scan_task.task_flag = 'stop'
        scan_task.save()
        models.BannerTask.objects.filter(scan_task_id=_id, execute_status=0).update(execute_status=3)
    elif ope == 'delete':
        paths = []
        if scan_task.port_result_path is None:
            paths.append(scan_task.port_result_path)
        if scan_task.report_result_path is None:
            paths.append(scan_task.report_result_path)
        results = models.BannerTask.objects.filter(scan_task_id=_id, execute_status=2).all()
        for banner in results:
            if banner.banner_result_path is not None:
                paths.append(banner.banner_result_path)
        models.BannerTask.objects.filter(scan_task_id=_id).delete()
        delete_file(paths)
    elif ope == 'cancel':
        models.ScanTask.objects.filter(id=_id).update(execute_status=4, task_flag=2)
        models.BannerTask.objects.filter(scan_task_id=_id).update(execute_status=4)
    return JsonResponse({"msg": "success"}, safe=False)


def task_process(task):
    execute = task.execute_status
    upload = task.upload_status
    process = len(task.protocol.split(",")) + 1
    current = 0
    if execute == 1:
        task.description = '正在探测存活主机'
        current = 0
    elif execute == 2 and upload == -1:
        bannerInfo = models.BannerTask.objects.filter(execute_status=1, scan_task_id=task.id).first()
        if bannerInfo is not None:
            task.description = '正在获取banner信息'+'(' + str(bannerInfo.port) + ': ' + str(bannerInfo.protocol) + ')'
        else:
            task.description = '正在获取banner信息'
        current = models.BannerTask.objects.filter(execute_status=2, scan_task_id=task.id).count()
    elif execute == 2 and upload == 1:
        task.description = '已完成'
        current = process
    elif execute == 0:
        task.description = '排队中'
    task.process = process
    task.current = current


def get_protocols(request):
    return JsonResponse({"port_protocol": common.port_protocols, "protocol_port": common.protocol_ports})
