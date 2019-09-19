from django.db import models

# Create your models here.
from django.utils import timezone


class ScanTask(models.Model):
    id = models.CharField(max_length=40, verbose_name="ID", primary_key=True)
    command = models.TextField(verbose_name="指令")
    port = models.IntegerField(verbose_name="端口", default=0)
    protocol = models.CharField(max_length=100, verbose_name="扫描协议")
    ip_range = models.CharField(max_length=100, verbose_name="要探测的IP网段, 零散的IP此处填 * ")
    ip_count = models.IntegerField(verbose_name="ip数量", default=0)
    open_port_count = models.IntegerField(verbose_name="开放端口数量", default=0)
    port_result_path = models.CharField(max_length=150, verbose_name="zmap结果存储路径")
    issue_time = models.DateTimeField(default=timezone.activate(timezone="UTC"), verbose_name="接收指令时间")
    finish_time = models.DateTimeField(verbose_name="全部执行完成时间", null=True)
    report_result_path = models.CharField(verbose_name="分析结果存储路径", max_length=200, null=True)
    report_file_md5 = models.CharField(verbose_name="分析报告的MD5值，用于完整性校验", null=True, max_length=40)
    report_size = models.IntegerField(verbose_name="压缩包大小", default=0)
    execute_status = models.IntegerField(verbose_name="执行状态(0-未执行,1-正在执行,2-执行完成,-1-执行失败)", default=0)
    send_banner_task = models.IntegerField(verbose_name="已完成端口扫描后，下发获取banner任务(0-未下发、1-已下发，-1下发失败)", default=0)
    banner_task_count = models.IntegerField(verbose_name="尚未完成的banner获取任务数量，数量为0即可回传结果到中心", default=-1)
    upload_status = models.IntegerField(verbose_name="上报中心状态(0-未上报,1-已上报,-1-不可上报状态)", default=-1)
    priority = models.IntegerField(verbose_name="扫描优先级", default=5)
    circulate_number = models.IntegerField(verbose_name="循环执行次数", default=0)

    def __str__(self):
        return self.command

    class Meta:
        verbose_name = "扫描指令"
        verbose_name_plural = verbose_name


class BannerTask(models.Model):
    id = models.CharField(max_length=40, verbose_name="ID", primary_key=True)
    command = models.TextField(verbose_name="指令")
    port = models.IntegerField(verbose_name="端口", default=0)
    protocol = models.CharField(max_length=100, verbose_name="扫描协议")
    ip_count = models.IntegerField(verbose_name="ip数量", default=0)
    scan_task_id = models.CharField(max_length=40, verbose_name="主任务ID")
    banner_result_path = models.CharField(max_length=150, verbose_name="zgrab结果存储路径")
    banner_size = models.IntegerField(verbose_name="banner生成文件大小", default=0)
    ztag_result_path = models.CharField(max_length=150, verbose_name="ztag结果存储路径", null=True)
    ztag_size = models.IntegerField(verbose_name="ztag生成文件大小", default=0)
    execute_status = models.IntegerField(verbose_name="执行状态(0-未执行,1-正在执行,2-执行完成,-1-执行失败)", default=0)
    ztag_status = models.IntegerField(verbose_name="ztag执行状态(0-未执行,1-执行完成,-1-不执行ztag)", default=-1)
    priority = models.IntegerField(verbose_name="扫描优先级", default=5)
    banner_success_count = models.IntegerField(verbose_name="成功获取banner数量", default=0)
    ztag_handle_count = models.IntegerField(verbose_name="指纹处理数量", default=0)
    create_time = models.DateTimeField(verbose_name="记录创建时间", null=True)
    finish_time = models.DateTimeField(verbose_name="执行完成时间", null=True)

    def __str__(self):
        return self.command

    class Meta:
        verbose_name = "banner获取"
        verbose_name_plural = verbose_name


class ReconRecordLog(models.Model):
    id = models.CharField(max_length=40, verbose_name="ID", primary_key=True)
    ip_count = models.IntegerField(verbose_name="ip数量", default=0)
    command = models.TextField(verbose_name="指令")
    success_count = models.IntegerField(verbose_name="成功数量", default=0)
    task_type = models.CharField(max_length=20, verbose_name="任务类型： banner/online")
    create_time = models.DateTimeField(verbose_name="记录创建时间", null=True)

    def __str__(self):
        return self.command

    class Meta:
        verbose_name = "任务执行情况"
        verbose_name_plural = verbose_name


class ReceiveScans(models.Model):
    ip = models.CharField(max_length=40, verbose_name="ip地址", primary_key=True)
    status = models.IntegerField(verbose_name="探测状态(0:待扫描,1:已经提取到扫描任务队列,2:待删除)", default=0)
    flag = models.IntegerField(verbose_name="0:代表批次探测,1:及时探测", default=0)

    def __str__(self):
        return self.ip

    class Meta:
        verbose_name = "探测队列"
        verbose_name_plural = verbose_name

