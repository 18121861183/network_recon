#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by zhaoyaochen on 19-7-3

import hashlib


def get_md5(content):
    """
    获取content的MD5值
    :param content:  utf-8编码字符串
    :return:
    """
    return hashlib.md5(content.encode('utf8')).hexdigest()


def get_sha1(content):
    """
    获取content的sha1值
    :param content:  utf-8编码字符串s
    :return:
    """
    return hashlib.sha1(content.encode('utf8')).hexdigest()


def get_sha256(content):
    """
    获取content的sha256值
    :param content:  utf-8编码字符串s
    :return:
    """
    return hashlib.sha256(content.encode('utf8')).hexdigest()


