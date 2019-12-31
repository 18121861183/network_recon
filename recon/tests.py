import csv
import ipaddress
import uuid

from django.test import TestCase

# Create your tests here.
# from django.utils import timezone
#
# print(timezone.now())

# address = hex(uuid.getnode())[2:]
# address = address.upper()
# result = '-'.join(address[i:i+2] for i in range(0, len(address), 2))
#
# for ip in list(ipaddress.ip_network("192.168.0.0/24", False).hosts()):
#     print(str(ip))

path = '/opt/recon/scan/20191225174347_1'
print(str(path).find("/"))
if path is not None and str(path).find("/") > -1:
    array = path.split("/")
    print(array[len(array)-1])
