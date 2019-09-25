
# default_protocol = ["ftp", "ssh", "telnet", "smtp", "pop3", "http", "fox", "bacnet",
#                     "dnp3", "imap", "ipp", "modbus", "mongodb", "mssql", "mysql", "ntp",
#                     "oracle", "postgres", "redis", "siemens", "smb", "amqp", "vnc", "dns",
#                     "ipmi", "ldap", "rdp", "rpc", "rsync", "sip", "snmp", "tftp"]
#
# us_ports = [21, 22, 23, 25, 80, 110, 137, 139, 161, 443, 445, 515, 1433, 1900, 3306,
#             3389, 6379, 7547, 8080, 9200, 22105, 37777]
#
#
# normal_ports = [13, 21, 22, 23, 25, 26, 53, 69, 80, 81, 88, 110, 111, 123, 135, 137,
#                 139, 161, 179, 264, 389, 443, 445, 465, 515, 520, 623, 636, 873, 902,
#                 992, 993, 995, 1234, 1241, 1433, 1521, 1604, 1701, 1900, 1967, 2181,
#                 3000, 3128, 3260, 3306, 3307, 3388, 3389, 4000, 4730, 5000, 5001,
#                 5060, 5353, 5357, 5400, 5555, 5672, 5900, 5938, 5984, 6000, 6379,
#                 6665, 6666, 6667, 6668, 6669, 7474, 7547, 7777, 8000, 8080, 8081, 8087,
#                 8089, 8834, 9200, 9999, 10000, 12345, 14000, 22105, 27017, 37777, 50000, 50100, 61613]


unfinished = ["serialNumbered", "javaRmi", "citrixApps",
              "smi", "munin", "appleAirportAdmin", "androidDebugBridge", "broadcastPcAnywhere", "weblogic",
              "spark", "yahooSmartTv", "bitcoin", "ethereumrpc", "gangliaXMLGridMonitor",
              "dvrVideo", "idevice"]

foreign_protocols = {
    21: ["ftp", "http", "ssh"],
    22: ["ssh", "http", "ftp"],
    23: ["telnet", "http", "ssh"],
    25: ["smtp", "http", "ftp"],
    80: ["http", "ssh", "ftp"],
    137: ["nbns", "http", "ssh"],
    139: ["nbss", "http", "ssh"],
    161: ["snmp", "http", "ssh"],
    443: ["http", "ssh"],
    445: ["smb", "http"],
    515: ["lpd", "http", "ssh"],
    1433: ["mssql", "http", "ssh"],
    1900: ["http", "upnp", "ssh"],
    3306: ["mysql", "http", "ssh"],
    3389: ["rdp", "http", "ssh"],
    6379: ["redis", "http", "ssh"],
    7547: ["http", "ssh", "ftp"],
    8080: ["http", "ssh", "ftp"],
    9200: ["http", "ssh", "elastic"],
    22105: ["http", "ssh"],
    37777: ["http", "ssh", "dahuaDvr"],
}

port_protocols = {
    7: ["echo", "http", "ssh"],
    11: ["http", "ssh", "ftp"],
    13: ["daytime", "ssh", "http"],
    17: ["qotd", "http", "ssh"],
    19: ["chargen", "http", "ssh", "ftp"],
    21: ["ftp", "http", "ssh"],
    22: ["ssh", "http", "ftp"],
    23: ["telnet", "http", "ssh", "ftp"],
    25: ["smtp", "http", "ftp"],
    26: ["smtp", "http", "ssh"],
    37: ["rdate", "http", "ssh"],
    49: ["http", "tacacsplus", "ssh"],
    53: ["dns", "http", "ssh"],
    69: ["tftp", "http", "ssh", "bittorrent"],
    70: ["gopher", "http", "ssh"],
    79: ["finger", "http", "ssh", "ftp"],
    80: ["http", "ssh", "ftp"],
    81: ["http", "ssh", "ftp"],
    82: ["http", "ssh", "ftp"],
    83: ["http", "ssh", "ftp"],
    84: ["http", "ssh", "ftp"],
    88: ["http", "ssh", "ftp"],
    102: ["siemens", "http", "ssh"],
    104: ["dicom", "http", "ssh"],
    110: ["pop3", "http", "ssh"],
    111: ["portmap", "ssh", "http"],
    113: ["identd", "http", "ssh"],
    119: ["nntp", "http", "ftp"],
    123: ["ntp", "http", "ssh"],
    135: ["dcerpc", "http", "ssh"],
    137: ["nbns", "http", "ssh"],
    139: ["nbss", "http", "ssh"],
    143: ["imap", "http", "ssh"],
    161: ["snmp", "http", "ssh"],
    162: ["http", "ssh", "ftp"],
    179: ["bgp", "http", "ssh"],
    199: ["smux", "http", "ssh"],
    264: ["cpfw", "http", "ssh"],
    389: ["ldap", "http", "ssh"],
    391: ["http", "ssh", "ftp"],
    443: ["http", "ssh", "icap"],
    444: ["http", "ssh", "ftp"],
    445: ["smb", "http", "ssh"],
    465: ["smtp", "http"],
    500: ["ikev2", "isakmp", "http"],
    502: ["modbus", "http", "ssh"],
    503: ["http", "modbus", "ssh"],
    515: ["lpd", "http", "ssh"],
    520: ["rip", "http", "ssh", "ftp"],
    523: ["ibmDb2", "http", "ssh", "ftp"],
    548: ["afp", "http", "ssh"],
    554: ["rtsp", "http", "ssh"],
    587: ["smtp", "http", "ftp"],
    623: ["ipmi", "http", "ssh", "ftp"],
    626: ["http", "ssh", "serialNumbered"],
    631: ["ipp", "http", "ssh"],
    636: ["ldap", "http", "ssh"],
    705: ["http", "ssh", "ftp"],
    771: ["http", "realport", "ssh"],
    789: ["redlion", "http", "ssh"],
    873: ["rsync", "http", "ssh"],
    880: ["http", "ssh", "ftp"],
    902: ["vmware", "http", "ftp"],
    992: ["http", "telnet", "ssh", "ftp"],
    993: ["imap", "http", "ssh", "ftp"],
    995: ["pop3", "http", "ssh"],
    1025: ["rtsp", "http", "dcerpc"],
    1026: ["http", "dcerpc", "ssh"],
    1027: ["dcerpc", "http", "ssh"],
    1080: ["socks4", "socks5", "http"],
    1099: ["http", "javaRmi", "ssh"],
    1177: ["http", "ssh", "ftp"],
    1194: ["openvpn", "http"],
    1200: ["codesys", "http", "ftp"],
    1201: ["http", "ssh", "ftp"],
    1234: ["http", "ssh", "ftp"],
    1241: ["http", "ssh", "ftp"],
    1311: ["http", "ssh", "ftp"],
    1344: ["icap", "http", "ssh"],
    1433: ["mssql", "http", "ssh"],
    1471: ["http", "ssh", "ftp"],
    1521: ["oracle", "http", "ftp"],
    1604: ["http", "citrixApps", "ssh", "ftp"],
    1701: ["l2tp", "http", "ssh", "ftp"],
    1723: ["pptp", "http", "ssh", "ftp"],
    1812: ["radius", "http", "ssh", "ftp"],
    1883: ["mqtt", "http", "ssh"],
    1900: ["http", "upnp", "ssh"],
    1911: ["fox", "http", "ssh"],
    1962: ["pcworx", "http", "ssh"],
    1967: ["http", "ssh", "ftp"],
    1991: ["http", "ssh", "ftp"],
    1993: ["http", "ssh", "ftp"],
    2000: ["bandwidthTest", "http", "ssh"],
    2080: ["http", "ssh", "ftp"],
    2082: ["http", "ssh", "ftp"],
    2083: ["http", "ssh", "ftp"],
    2086: ["http", "ssh", "ftp"],
    2087: ["http", "ssh", "ftp"],
    2094: ["http", "ssh", "ftp"],
    2121: ["http", "ssh", "ftp"],
    2123: ["gtp", "http", "ssh", "ftp"],
    2181: ["zookeeper", "http", "ssh"],
    2222: ["cspv4", "ssh", "http", "ftp"],
    2323: ["telnet", "http", "ssh"],
    2332: ["telnet", "http", "ssh"],
    2375: ["docker", "http", "ssh"],
    2376: ["docker", "http", "ssh"],
    2379: ["etcd", "http", "ssh"],
    2401: ["cvspserver", "http", "ssh"],
    2404: ["iec104", "http", "ssh"],
    2427: ["mgcp", "http", "ssh"],
    2455: ["codesys", "http", "ftp"],
    2480: ["orientdb", "http", "ssh", "ftp"],
    2628: ["http", "ssh", "ftp"],
    3000: ["http", "ssh", "ftp"],
    3128: ["http", "ssh", "ftp"],
    3260: ["iscsi", "http", "ssh"],
    3306: ["mysql", "http", "ssh"],
    3307: ["mysql", "http", "ssh"],
    3310: ["clamav", "http", "ssh", "ftp"],
    3388: ["rdp", "http", "ssh"],
    3389: ["rdp", "http", "ssh"],
    3541: ["http", "ssh", "ftp"],
    3542: ["http", "ssh", "ftp"],
    3689: ["http", "ssh", "ftp"],
    3749: ["http", "ssh", "ftp"],
    3780: ["http", "ssh", "ftp"],
    3784: ["ventrilo", "http", "ssh"],
    4000: ["http", "ssh", "ftp"],
    4022: ["http", "ssh", "ftp"],
    4040: ["http", "ssh", "ftp"],
    4063: ["http", "telnet", "ssh"],
    4064: ["http", "ssh", "ftp"],
    4070: ["vertedge", "http", "ssh", "ftp"],
    4369: ["epmd", "http", "ssh"],
    4443: ["http", "ssh", "ftp"],
    4567: ["http", "ssh", "ftp"],
    4712: ["http", "ssh", "ftp"],
    4730: ["http", "ssh", "gearman"],
    4786: ["smi", "http", "ssh"],
    4800: ["moxaNport", "http", "ssh"],
    4848: ["http", "ssh", "ftp"],
    4911: ["fox", "http", "ssh", "ftp"],
    4949: ["munin", "http", "ssh"],
    5000: ["vtun", "http", "ssh"],
    5001: ["http", "ssh", "ftp"],
    5006: ["http", "ssh", "ftp"],
    5007: ["melsecQ", "http", "ssh", "ftp"],
    5009: ["appleAirportAdmin", "http", "ftp"],
    5060: ["sip", "http", "ssh"],
    5094: ["hartip", "http", "ssh", "ftp"],
    5222: ["xmpp", "http", "ssh"],
    5269: ["xmpp", "http", "ssh"],
    5351: ["natpmp", "http", "ssh"],
    5353: ["mdns", "http", "ssh", "ftp"],
    5357: ["http", "ssh", "ftp"],
    5400: ["http", "ssh", "ftp"],
    5432: ["postgres", "http", "ssh"],
    5555: ["http", "androidDebugBridge", "ssh"],
    5560: ["http", "ssh", "ftp"],
    5632: ["broadcastPcAnywhere", "http", "ssh", "ftp"],
    5672: ["amqp", "http", "ssh"],
    5678: ["http", "ssh", "ftp"],
    5683: ["coap", "http", "ssh"],
    5900: ["vnc", "http", "ssh"],
    5901: ["vnc", "http", "ssh"],
    5938: ["http", "teamview", "ssh"],
    5984: ["couchdb", "http", "ssh", "ftp"],
    5985: ["http", "ssh", "ftp"],
    5986: ["http", "ssh", "ftp"],
    6000: ["http", "ssh", "x11"],
    6001: ["x11", "http", "ssh"],
    6379: ["redis", "http", "ssh"],
    6664: ["http", "ssh", "ftp"],
    6665: ["http", "ssh", "irc"],
    6666: ["http", "ssh", "irc"],
    6667: ["http", "ssh", "irc"],
    6668: ["http", "ssh", "irc"],
    6669: ["http", "ssh", "irc"],
    6969: ["bittorrent", "http", "ssh"],
    7001: ["weblogic", "http", "ssh"],
    7071: ["http", "ssh", "ftp"],
    7077: ["http", "spark", "ssh"],
    7288: ["http", "ssh", "ftp"],
    7474: ["http", "ssh", "ftp"],
    7547: ["http", "ssh", "ftp"],
    7634: ["hddtemp", "http", "ssh"],
    7777: ["http", "ssh", "ftp"],
    7779: ["http", "ssh", "ftp"],
    8000: ["shoutcast", "http", "ssh"],
    8001: ["rtsp", "http", "ssh"],
    8008: ["http", "ssh", "ftp"],
    8009: ["http", "ajp", "ssh"],
    8010: ["http", "ssh", "ftp"],
    8060: ["http", "ssh", "ftp"],
    8069: ["http", "ssh", "ftp"],
    8080: ["sybase", "http", "ssh", "ftp"],
    8081: ["http", "ssh", "mysql"],
    8086: ["http", "ssh", "ftp"],
    8087: ["riak", "http", "ssh", "ftp"],
    8089: ["http", "ssh", "ftp"],
    8090: ["http", "ssh", "ftp"],
    8098: ["http", "ssh", "ftp"],
    8099: ["yahooSmartTv", "http", "ssh", "ftp"],
    8112: ["http", "ssh", "ftp"],
    8139: ["http", "ssh", "ftp"],
    8161: ["http", "ssh", "ftp"],
    8200: ["http", "ssh", "ftp"],
    8291: ["winbox", "http", "ftp"],
    8333: ["bitcoin", "http", "ssh"],
    8334: ["http", "ssh", "ftp"],
    8377: ["http", "ssh", "ftp"],
    8378: ["http", "ssh", "ftp"],
    8443: ["http", "ssh", "ftp"],
    8545: ["http", "ethereumrpc", "ssh", "ftp"],
    8554: ["rtsp", "http", "ssh"],
    8649: ["gangliaXMLGridMonitor", "http", "ssh"],
    8834: ["http", "ssh", "ftp"],
    8880: ["http", "ssh", "ftp"],
    8888: ["ssdb", "http", "ssh"],
    8889: ["http", "ssh", "ftp"],
    9000: ["dvrVideo", "http", "ssh"],
    9003: ["http", "ssh", "ftp"],
    9010: ["http", "ssh", "ftp"],
    9042: ["cassandra", "http", "ssh"],
    9080: ["http", "ssh", "ftp"],
    9191: ["http", "ssh", "ftp"],
    9200: ["http", "ssh", "elastic"],
    9333: ["http", "litecoin", "ssh"],
    9418: ["http", "git", "ssh"],
    9443: ["http", "ssh", "ftp"],
    9595: ["http", "ssh", "ftp"],
    9600: ["omron", "http", "ssh", "ftp"],
    9944: ["http", "ssh", "ftp"],
    9981: ["http", "ssh", "ftp"],
    9999: ["javaRmi", "http", "ssh"],
    10000: ["ndmp", "http", "ssh"],
    10001: ["atg", "ubiquitiDiscover", "http"],
    10243: ["http", "ssh", "ftp"],
    10333: ["http", "ssh", "ftp"],
    11001: ["fix", "http", "ssh", "ftp"],
    11211: ["memcache", "http", "ssh"],
    11300: ["beanstalk", "http", "ssh"],
    12345: ["http", "ssh", "ftp"],
    13579: ["http", "ssh", "ftp"],
    14000: ["http", "ssh", "ftp"],
    14147: ["http", "ssh", "ftp"],
    14265: ["iotaRpc", "rpc", "http", "ssh", "ftp"],
    16010: ["http", "ssh", "ftp"],
    16992: ["http", "ssh", "ftp"],
    16993: ["http", "ssh", "ftp"],
    17185: ["wdbrpc", "http", "ssh"],
    18081: ["monero", "rtsp", "http", "ssh"],
    18245: ["geSrtp", "http", "ssh", "ftp"],
    20000: ["dnp3", "http", "ssh", "ftp"],
    20547: ["proconos", "http", "ssh", "ftp"],
    20574: ["http", "ssh", "ftp"],
    22105: ["vrv", "http", "ssh"],
    23023: ["telnet", "http", "ssh"],
    23424: ["http", "ssh", "ftp"],
    25105: ["http", "ssh", "ftp"],
    27015: ["sourceRcon", "steamA2s", "http"],
    27017: ["http", "ssh", "mongodb"],
    28017: ["http", "ssh", "ftp"],
    28784: ["ecom", "http"],
    30311: ["gardasoft", "http", "ssh"],
    30718: ["lantronix", "http", "ssh", "ftp"],
    32400: ["http", "ssh", "ftp"],
    32768: ["http", "ssh", "ftp"],
    33338: ["nanocoreRat", "http", "ssh", "ftp"],
    37777: ["http", "ssh", "dahuaDvr"],
    44818: ["enip", "http", "ssh"],
    45554: ["http", "ssh", "ftp"],
    47808: ["bacnet", "http", "ssh"],
    48899: ["http", "ssh", "ftp"],
    49152: ["wemo", "http", "ssh"],
    49153: ["wemo", "http", "ssh"],
    50000: ["http", "ssh", "db2"],
    50070: ["rtsp", "http", "ssh"],
    50100: ["gpgga", "http", "rifatron", "ftp"],
    51106: ["rtsp", "http", "ssh"],
    55553: ["rtsp", "http", "ssh"],
    59110: ["http", "ssh", "ftp"],
    61613: ["http", "ssh", "stomp"],
    61616: ["activemq", "http", "ssh"],
    62078: ["idevice", "http", "ssh"],
    64738: ["mumble", "http", "ssh"],
}


ztag_command = {
    'ftp': '-P ftp -S banner',
    'ssh': '-P ssh -S v2',
    'telnet': '-P telnet -S banner',
    'smtp': '-P smtp -S starttls',
    'http': '-P http -S get',
    'pop3': '-P pop3 -S starttls',
    'smb': '-P smb -S banner',
    'imap': '-P imap -S starttls',
    'modbus': '-P modbus -S device_id',
    'mssql': '-P mssql -S banner',
    'oracle': '-P oracle -S banner',
    'fox': '-P fox -S device_id',
    'mysql': '-P mysql -S banner',
    'postgres': '-P postgres -S banner',
    'mongodb': '-P mongodb -S banner',
    'bacnet': '-P bacnet -S device_id',
    'dnp3': '-P dnp3 -S status',
}
