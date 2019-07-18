#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by zhaoyaochen on 19-7-3
import time


def get_now_timestamp():
    return round(time.time())


def get_date_format(timestamp):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))


def get_date_format_day(timestamp):
    return time.strftime('%Y%m%d', time.localtime(timestamp))


def get_now_day_str():
    return get_date_format_day(get_now_timestamp())


