# Generated by Django 2.2.3 on 2019-07-08 05:23

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='BannerTask',
            fields=[
                ('id', models.CharField(max_length=40, primary_key=True, serialize=False, verbose_name='ID')),
                ('command', models.TextField(verbose_name='指令')),
                ('port', models.IntegerField(default=0, verbose_name='端口')),
                ('protocol', models.CharField(max_length=100, verbose_name='扫描协议')),
                ('ip_count', models.IntegerField(default=0, verbose_name='ip数量')),
                ('scan_task_id', models.CharField(max_length=40, verbose_name='主任务ID')),
                ('banner_result_path', models.CharField(max_length=150, verbose_name='zgrab结果存储路径')),
                ('ztag_result_path', models.CharField(max_length=150, null=True, verbose_name='ztag结果存储路径')),
                ('execute_status', models.IntegerField(default=0, verbose_name='执行状态(0-未执行,1-正在执行,2-执行完成,-1-执行失败)')),
                ('ztag_status', models.IntegerField(default=-1, verbose_name='ztag执行状态(0-未执行,1-执行完成,-1-不执行ztag)')),
                ('priority', models.IntegerField(default=5, verbose_name='扫描优先级')),
                ('banner_success_count', models.IntegerField(default=0, verbose_name='成功获取banner数量')),
                ('ztag_handle_count', models.IntegerField(default=0, verbose_name='指纹处理数量')),
                ('create_time', models.DateTimeField(null=True, verbose_name='记录创建时间')),
                ('finish_time', models.DateTimeField(null=True, verbose_name='执行完成时间')),
            ],
            options={
                'verbose_name': 'banner获取',
                'verbose_name_plural': 'banner获取',
            },
        ),
        migrations.CreateModel(
            name='ReconRecordLog',
            fields=[
                ('id', models.CharField(max_length=40, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_count', models.IntegerField(default=0, verbose_name='ip数量')),
                ('command', models.TextField(verbose_name='指令')),
                ('success_count', models.IntegerField(default=0, verbose_name='成功数量')),
                ('task_type', models.CharField(max_length=20, verbose_name='任务类型： banner/online')),
                ('create_time', models.DateTimeField(null=True, verbose_name='记录创建时间')),
            ],
            options={
                'verbose_name': '任务执行情况',
                'verbose_name_plural': '任务执行情况',
            },
        ),
        migrations.CreateModel(
            name='ScanTask',
            fields=[
                ('id', models.CharField(max_length=40, primary_key=True, serialize=False, verbose_name='ID')),
                ('command', models.TextField(verbose_name='指令')),
                ('port', models.IntegerField(default=0, verbose_name='端口')),
                ('protocol', models.CharField(max_length=100, verbose_name='扫描协议')),
                ('ip_range', models.CharField(max_length=100, verbose_name='要探测的IP网段, 零散的IP此处填 * ')),
                ('ip_count', models.IntegerField(default=0, verbose_name='ip数量')),
                ('open_port_count', models.IntegerField(default=0, verbose_name='开放端口数量')),
                ('port_result_path', models.CharField(max_length=150, verbose_name='zmap结果存储路径')),
                ('issue_time', models.DateTimeField(default=None, verbose_name='接收指令时间')),
                ('finish_time', models.DateTimeField(null=True, verbose_name='全部执行完成时间')),
                ('report_result_path', models.CharField(max_length=200, null=True, verbose_name='分析结果存储路径')),
                ('report_file_md5', models.CharField(max_length=40, null=True, verbose_name='分析报告的MD5值，用于完整性校验')),
                ('execute_status', models.IntegerField(default=0, verbose_name='执行状态(0-未执行,1-正在执行,2-执行完成,-1-执行失败)')),
                ('send_banner_task', models.IntegerField(default=0, verbose_name='已完成端口扫描后，下发获取banner任务(0-未下发、1-已下发，-1下发失败)')),
                ('banner_task_count', models.IntegerField(default=-1, verbose_name='尚未完成的banner获取任务数量，数量为0即可回传结果到中心')),
                ('upload_status', models.IntegerField(default=-1, verbose_name='上报中心状态(0-未上报,1-已上报,-1-不可上报状态)')),
                ('priority', models.IntegerField(default=5, verbose_name='扫描优先级')),
            ],
            options={
                'verbose_name': '扫描指令',
                'verbose_name_plural': '扫描指令',
            },
        ),
    ]
