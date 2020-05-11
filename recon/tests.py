
import json

path = '/home/cuckoo/result.json'
result = open(path, "r+")
for line in result:
    if line.find('"status":"success"') > -1:
        obj = json.loads(line.strip())
        print(obj['ip'])
    else:
        print(line.strip())


