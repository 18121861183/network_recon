#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by zhaoyaochen on 19-9-3
import math
import os
import subprocess
import tarfile
import uuid

from recon import date_util


def gen_report(param_info, report_info, number, base_path):
    report_list = []
    for i in range(number):
        report = dict()
        for key in report_info.keys():
            files = report_info.get(key)
            if isinstance(files, list):
                try:
                    report[key] = files[i]
                except:
                    continue
            else:
                if i == 0:
                    report[key] = files

        file_path = base_path+str(uuid.uuid4())+".tar.gz"
        with tarfile.open(file_path, 'w:gz') as tar:
            tar.add(param_info, arcname='param.json')
            for msg in report.keys():
                tar.add(report.get(msg), arcname=msg)
        for key in report.keys():
            os.remove(report.get(key))
        report_list.append(file_path)
    os.remove(param_info)
    return report_list


def split_file(path=None, max_size=1024*1024*100):
    if path is None:
        return None
    size = os.path.getsize(path)
    if size > max_size:
        # 处理文件分割
        number = math.ceil(size / max_size)
        print(path, "将分割成压缩包:", number, "个")

        # 处理目录准备
        max_file_split_path = "/data/deal_path/"
        if os.path.exists(max_file_split_path) is False:
            os.makedirs(max_file_split_path)

        task_path = date_util.get_format_date("%m%d%H%M%S")
        base_path = max_file_split_path+task_path+"/"
        if os.path.exists(max_file_split_path+task_path) is False:
            os.makedirs(max_file_split_path+task_path)

        tar = tarfile.open(path)
        tar.extractall(max_file_split_path+task_path)
        param_info = None
        report_info = dict()
        for filename in os.listdir(base_path):
            if filename == 'param.json':
                param_info = base_path+filename
                continue
            if os.path.getsize(base_path+filename) > 1024*1024:
                split_files = split_line(base_path+filename, number)
                report_info[filename] = split_files
            else:
                report_info[filename] = str(base_path+filename)

        return gen_report(param_info, report_info, number, base_path)
    else:
        return [path]


def split_line(path, number):
    _result = subprocess.getoutput("wc -l " + path)
    singer_number = math.ceil(int(_result.split(" ")[0]) / number)
    files = []
    with open(path, "r") as file:
        number = 1
        count_line = 0
        _file = open(path+str(number), "w")
        files.append(path+str(number))
        for line in file:
            if count_line == singer_number:
                _file.close()
                number += 1
                _file = open(path + str(number), "w")
                files.append(path + str(number))
                count_line = 0
            _file.write(line)
            count_line += 1
        _file.close()
    os.remove(path)
    return files
