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
# print(result)

result = ipaddress.ip_address('3221225985')
print(str(result))

