import sys
import re
import time
from Colors import *

def hPad(lenHeader):
    return int(( 80 - lenHeader)  / 2)
"""
Determine if device is Huawei
Return True if it's a Huawei
"""
def isHuawei(prompt):
    assert(prompt != None), "[-] No prompt given"
    if "<" in prompt:
        return True
    return False

"""
Validate IP address, remove space
Return sanitized IP if valid, else try again
"""
def validIP(ip_addr):
    if (ip_addr == ''):
        print(Cs.FAIL + "[-] Error: no IP address given" + Cs.ENDC)
        sys.exit(1)
    re_pattern = r'^\d+\.\d+\.\d+\.\d+$'
    ip = "".join(ip_addr.split())
    if not bool(re.search(re_pattern, ip)):
        print (Cs.FAIL + "[-] error: IP address is not valid" + Cs.ENDC)
        ip = validIP(str(input("@IP PoP: ")))
    return ip

"""
Validate VLAN id, remove space aside
Return sanitized VLAN
"""
def validVlan(vlan_id):
    assert(vlan_id != ""), "[-] Error: no vlan given!"
    if (vlan_id == ""):
        print(Cs.FAIL + "[-] Error: no VLAN given" + Cs.ENDC)
        sys.exit(1)
    re_pattern = r'^\d+$'
    vlan = "".join(vlan_id.split())
    if not bool(re.search(re_pattern, vlan_id)):
        print(Cs.FAIL + "[-] VLAN is not valid" + Cs.ENDC)
        validVlan(str(input("VLAN id: ")))
    return vlan

def dfs(root):
    if not root:
        return []
    res = []
    stack = [(root, 0)]
    while stack:
        curr,level = stack.pop()
        if len(res) < level + 1:
            res[level].append(curr.hostname)
        if curr.right:
            stack.append((curr.right, level+1))
        if curr.left:
            stack.append((curr.left, level+1))
    return res

"""
Fct: Retrieve all ports from line after show vlan id
Arg: String line
Return array of ports
"""
def get_ports(line):
    line = re.findall(r'active([\s\S]+)', line)[0]
    regex = re.compile(r'Po')
    # Match Fa Gi Po Te
    port_regex = r'(Fa\d+/\d+|Po\d+|Te\d+/\d+|Gi\d+/\d+)'
    #Former solution but issued wrong interface
    #ports = re.findall(r'([FaGiTePo]+\d+[/]*\d*)', line)
    ports = re.findall(port_regex, line)
    for i in range(len(ports)):
        ports[i] = regex.sub('port-c',ports[i])
    #print(ports)
    return ports
"""
Compare hostname with data hosts array
Arg: hostname (string), arr (list) of hostname and ip address
return ip adress of an hostname
"""
def get_ip_from_desc(hostname, hosts_list):
    assert(hosts_list != None), "Hosts list not created"
    length = len(hosts_list)
    #print(hosts_list)
    for i in range(10, length):
        if hostname in hosts_list[i]:
            return match_ip_addr(hosts_list[i])
"""
Fct: Retrieve hostname from IP address, parse the hosts file on PF2

"""
#FIXME non greedy match, issue on bad hostname
def get_hostname_from_ip(ip, hosts_list):
    assert(hosts_list != None), "Hosts list not created"
    length = len(hosts_list)
    for i in range(10, length):
        if ip in hosts_list[i]:
            return match_hostname(hosts_list[i])

"""
Fct: Match the hostname from a line in hosts file
"""
def match_hostname(line):
    regex = r'\d+\.\d+\.\d+\.\d+[ ]+(\S+)'
    hostname = re.findall(regex, line)
    return hostname[0]
"""
Fct: Retrieve the ip address from a line i.e "10.129.1.81 HotelTechno-7609..."
     got from get_ip_from desc function
Arg:
"""
def match_ip_addr(line):
    # Match X.X.X.X with X an integer
    regex = r'\d+\.\d+\.\d+.\d+'
    ip = re.findall(regex, line)
    return ip[0] if ip else None
"""
Fct: Retrieve the full service name or the neighbour hostname after show interfaces desc
"""
def get_hostname_desc(description):
    assert(description != None), "No description given"
    if 'AC' in description:
        regex = r'(AC\d+[^"]+)'
        host = re.findall(regex, description, re.I)
        return host[0] if host else "No service name found in description\n" + description
    elif 'CN' in description:
        regex = r'(CN[^"]+)'
        host = re.findall(regex, description)
        return host[0] if host else "Collecte name not found in description\n" + description
    elif 'FR' in description:
        regex = r'(FR\d+[^"]+)'
        host = re.findall(regex, description, re.I)
        return host[0] if host else "No service name found in description\n" + description
    regex = r'TRUNK[MPLS-]{0,5} ([^ ]+) '
    host = re.findall(regex, description, re.I)
    if not host:
        all_regex = r'[updown\s]+(\S+[\S\s]*)'
        host = re.findall(all_regex, description)
    assert(host), "No hostname found in description:\n" + description
    return host[0]

"""
Fct: Retrieve interface, ip address, status from mpls command
Arg: Array mpls_out
"""
def get_mpls_interf_ip_status(mpls_out, hostname, vlan):
    assert(mpls_out != None), "No mpls output"
    re_interface = r'([FaGiTePo]+\d+[/]?\d*)'
    re_ip =r'(\d+\.\d+\.\d+\.\d+)'
    re_status = r'(UP|DOWN)'
    res = [[],[],[]]
    lines = mpls_out[4:]
    if len(lines[0]) == 0:
        print (Cs.WARNING + "[*] WARNING! VLAN {} does not exist on {}".format(vlan, hostname) + Cs.ENDC)
        return None, None, None
    for l in lines:
        port = re.findall(re_interface, l)
        if port:
            port = port[0]
            interface = re.sub(r'Po', 'port-c', port)
            res[0].append(interface)
        ip = re.findall(re_ip, l)
        if ip:
            res[1].append(ip[0])
        status = re.findall(re_status, l)
        if status:
            res[2].append(status[0])
    return res

##
#Extracted data from RAD are processed by functions below
#
#

# Fct: remove special char \r in list
#
def remove_backr(arr):
    regex = re.compile(r'\r')
    res = list()
    for i in range(len(arr)):
        if arr[i] == '\r':
            continue
        res.append(regex.sub('', arr[i]))
    return res
"""
Fct: Match any flow related to the vlan id
Return list of flow profiles
"""
def find_flows(arr, vlan):
    arr = remove_backr(arr)
    #print(arr)
    flows = list()
    for line in arr:
        if 'flow' in line and vlan in line:
            flows.append(line)
    if len(flows) < 2:
        print(Cs.WARNING + "[*] WARNING! No flow related to vlan {} found on the Rad".format(vlan) + Cs.ENDC)
    elif len(flows) > 2:
        print(Cs.WARNING + "[*] WARNING! aux.find_flows: more than two flows matched" + Cs.ENDC)
    return flows
"""
Fct : Match the ethernet port of a Rad
"""
def find_port_eth(info_d):
    re_eth = r'ethernet\s+\d+[/]?\d*'
    eth_match = re.findall(re_eth, info_d)
    #DEBUG print("PORT ETH: " + str(eth_match))
    return eth_match
"""
Fct: return True if speed > 100Mbps
"""
def status_speed(inf_d):
    if "Gbps" in inf_d:
        return True
    re_speed_v3 = r'policer [profile/aggregate]+ \S+-(\d+)\"'
    re_speed_BPE = r'policer [profile/aggregate]+ [^\d]+(\d+)Mbps\"'
    speed_match_v3 = re.findall(re_speed_v3, inf_d)
    speed_match_BPE = re.findall(re_speed_BPE, inf_d)
    if len(speed_match_v3) == 2:
        # DEBUG print("speed " + str(speed_match_v3))
        if int(speed_match_v3[0]) > 100:
            return True
        return False
    elif len(speed_match_BPE) == 2:
        if int(speed_match_BPE[0]) > 100:
            return True
        return False
    elif len(speed_match_v3) > 0 and len(speed_match_BPE) > 0:
        print(Cs.WARNING + "[*] WARNING! aux.status_speed has matched more or less than one value" + Cs.ENDC)
    #DEBUG print("DEBUG aux.status_speed *inf_d:\n" + inf_d + "DEBUG END")
    #DEBUG print("speed match" + str(speed_match_v3 + speed_match_BPE))
    #sys.exit(1)
    return True

##############################################
# All function dedicated to HUAWEI are below #
##############################################
"""
Fct: return the global interface, ip destination, session state, AC status
param dis_mpls string output of display mpls l2
"""
def hw_port_ip_status(disp_mpls):
    re_port = r'X?GigabitEthernet\d+/\d+/\d+'
    re_ip = r'destination[: ]+(\S+)'
    re_session_st = r'session state[: ]+(\S+)'
    re_ac_st = r'AC status[: ]+(\S+)'

    port = re.findall(re_port, disp_mpls)[0]
    assert(port != None), "Port is None"
    ip = re.findall(re_ip, disp_mpls)[0]
    assert(ip != None), "IP is None"
    session_st = re.findall(re_session_st, disp_mpls)[0]
    assert(session_st != None), "Session state is None"
    ac_st = re.findall(re_ac_st, disp_mpls)[0]
    assert(ac_st != None), "AC state is None"
    #PRINT DEBUG
    #print(port)
    #print(ip)
    #print("session status " + session_st)
    #print("AC status " + ac_st)
    return [port, ip, session_st, ac_st]

"""
return serviceID-Operator-SiteA-IP without space between
Param desc "GE1/0/8     up      up      AC003822-OPER-SIT        E_A-IP
"""
def hw_description(desc):
   re_sid = r'up\s+up\s+([\S\s|]+)'
   sid_match = re.findall(re_sid, desc)
   assert(sid_match[0] != None), "Servce id not found, sid_match[0] is None"
   sid_match[0] = re.sub(r'\s*', '', sid_match[0])
   return sid_match[0]

