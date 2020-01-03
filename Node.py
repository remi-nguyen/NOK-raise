#!/usr/bin/env python3

from Colors import *
from pexpect import pxssh
from collections import deque
import pexpect
import getpass
import time
import re
import sys
import aux_fct


class Node:
    def __init__(self, ip_addr, hostname=None):
        self.hostname = hostname
        self.ip_addr = ip_addr
        self.isHuawei = False
        self.left = None
        self.right = None
        self.rad = None
        self.prompt = None
        # Dict. {Port: hostname}
        self.ports_host_dict = dict()
        # Dict. {Hostname: IP_addr}
        self.hosts_ip_dict = dict()
        self.status = str()
        self.verification = str()

    def printTree(self):
        if self.left:
            self.left.printTree()
        print (self.hostname)
        if self.right:
            self.right.printTree()

    def session_A_cisco(self, vlan_id):
        global CPE
        global hosts_list
        plate_forme2 = '172.16.128.105'
        username_pf2 = 'tibco'
        s = pxssh.pxssh()
        # Try to connect to Plate-Forme 2
        assert(s.login(plate_forme2, username_pf2, password)), "Not connected to PF2"
        # Retrieve the ip address of all hostname
        s.sendline("cat /etc/hosts")
        s.prompt()
        # All hosts / IP, needed to find the @IP from an hostname
        hosts_list = s.before.decode("utf-8").split("\r\n")[10:]
        # Try landing a connection on PoP
        try:
            s.sendline("telnet " + self.ip_addr)
            s.expect('sername')
            s.sendline(username_equ)
            s.expect('assword')
            s.sendline(password)
            s.expect('<?[A-Za-z0-9-_]+[>#]+')
            self.prompt = s.after.decode("utf-8")
        except:
            print(Cs.FAIL + "Error: could not connect to {} {}".format(self.ip_addr, self.hostname) + Cs.ENDC)
            sys.exit(1)
            return
        # Return true if device is Huawei
        if aux_fct.isHuawei(self.prompt):
            self.hostname = self.prompt[1:-1]
            print(Cs.UNDERLINE + "[+] Device {} is a Huawei".format(self.hostname) + Cs.ENDC)
            self.isHuawei = True
            print(Cs.OKBLUE + "[+]{} Connecting to {}".format(Cs.ENDC, self.hostname))
            self.session_huawei(vlan_id)
            s.close()
            return
        elif self.hostname == None:
            self.hostname = self.prompt[:-1]
        print(Cs.OKBLUE + "[+]{} Connected to {}".format(Cs.ENDC, self.hostname))
        # Add ip device in visited node list
        visited_nodes.append(self.ip_addr)
        visited_nodes_name.append(self.hostname)
        s.sendline("enable")
        s.sendline(password)
        #print("Enable Mode")
        s.expect('[A-Z-a-z0-9_-]+#')
        self.prompt = s.after.decode("utf-8")
        # Test global var
        s.sendline("show vlan id " + vlan_id)
        s.expect(self.prompt)
        res = s.before.decode("utf-8").split("\r\n")
        # res[4] contain info from cmd: show vlan id
        #print(res[4])
        desc_ip_d = dict()
        # IF global vlan id exists !
        if len(res) > 4:
            # port_arr: list of ports
            port_arr = aux_fct.get_ports(res[4])

            ports_description = list()
            for port in port_arr:
                cmd = "show interfaces " + port + " description"
                s.sendline(cmd)
                s.expect(self.prompt)
                # var description is list, cmd:interface up up FR00XXXX-Ope-Client-IP
                description = s.before.decode("utf-8").split("\r\n")[2]
                host_desc = aux_fct.get_hostname_desc(description)
                self.ports_host_dict[port] = host_desc
                #print("Port-host: " + str(self.ports_host_dict))
                host_ip_addr = aux_fct.get_ip_from_desc(host_desc, hosts_list)
                if host_ip_addr != None:
                    desc_ip_d[host_desc] = host_ip_addr
                # Process the description to find IP addr of the Rad
                rad_ip = aux_fct.match_ip_addr(host_desc)
                s.sendline("show spanning-tree vlan " + vlan_id)
                s.expect(self.prompt)
                span_tree_out = s.before.decode('utf-8').split("\r\n")
                # My verification
                verif_header = " {} {} ".format(self.hostname, self.ip_addr)
                pad = aux_fct.hPad(len(verif_header))
                self.verification = "\n{} {} {} {}\n\n".format('='*pad, self.hostname, self.ip_addr, '='*pad)
                self.verification += '\n'.join(span_tree_out)
                for p,h in self.ports_host_dict.items():
                    self.verification += p + '\t\t' + h + '\n'

                if CPE == True and rad_ip != None:
                    CPE = False
                    #print("{} -> {}".format(host_desc, rad_ip))
                    self.rad = Node(rad_ip)
                    print(Cs.OKBLUE + "[+]{} Connecting to CPE {}".format(Cs.ENDC, rad_ip))

                    self.rad.session_rad(vlan_id)
                elif CPE == False and rad_ip != None:
                    #print("{} -> {}".format(host_desc, rad_ip))
                    self.rad = Node(rad_ip)
                    print(Cs.OKBLUE + "[+]{} Connecting to Collecte {}".format(Cs.ENDC, rad_ip))

                    self.rad.session_rad(vlan_id)
            print(Cs.OKBLUE + "[+]{} Check on {}{} done".format(Cs.ENDC, self.hostname, Cs.OKGREEN) + Cs.ENDC)
            for host_desc, host_ip_addr in desc_ip_d.items():
                # Var host_ip_addr is 1.1.1.1 format
                if host_ip_addr != None and host_ip_addr not in visited_nodes:
                    self.hosts_ip_dict[host_desc] = host_ip_addr
                    if self.left == None:
                        self.left = Node(host_ip_addr, host_desc)
                        self.left.session_A_cisco(vlan_id)
                    elif self.right == None:
                        self.right = Node(host_ip_addr, host_desc)
                        self.right.session_A_cisco(vlan_id)
                    else:
                        print(Cs.WARNING + "[*] WARNING! More than two child nodes are necessary on {}".format(self.hostname) + Cs.ENDC)
        # IF MPLS exits
        else:
            verif_header = " {} {} ".format(self.hostname, self.ip_addr)
            pad = aux_fct.hPad(len(verif_header))
            self.verification = "\n{} {} {} {}\n\n".format('='*pad, self.hostname, self.ip_addr, '='*pad)
            s.sendline("show mpls l2transport vc " + vlan_id)
            s.expect(self.prompt)
            mpls_output = s.before.decode("utf-8").split("\r\n")
            self.verification += '\n'.join(mpls_output)
            # Get interface, ip, status from cmd: shpw mpls l2 vc VLAN
            #mpls_int, mpls_ip, mpls_status = aux_fct.get_mpls_interf_ip_status(mpls_output, self.hostname, vlan_id)
            # var port_ip_status is 2D list := [[port],[IP],[status]]
            port_ip_status = aux_fct.get_mpls_interf_ip_status(mpls_output, self.hostname, vlan_id)
            mpls_int = port_ip_status[0][0]
            for sta in port_ip_status[2]:
                upDown = None
                if sta == 'UP':
                    upDown = Cs.OKGREEN
                else:
                    upDown = Cs.FAIL
                print("[*] MPLS Status is {}{}{}".format(upDown, sta, Cs.ENDC))
            # Get the hostname from interface
            # var mpls_int is like Gi7/2 or Po1
            s.sendline("show interfaces " + mpls_int + " description")
            s.expect(self.prompt)
            int_desc_output = s.before.decode("utf-8").split("\r\n")[2]
            # If POP is PE
            rad_ip = aux_fct.match_ip_addr(int_desc_output)
            if CPE == True and rad_ip != None:
                CPE = False
                self.rad = Node(rad_ip)
                print(Cs.OKBLUE + "[+]{} Connecting to CPE {}".format(Cs.ENDC, rad_ip))
                self.rad.session_rad(vlan_id)

            elif CPE == False and rad_ip != None:
                self.rad = Node(rad_ip)
                print(Cs.OKBLUE + "[+]{} Connecting to Collecte {}".format(Cs.ENDC, rad_ip))
                self.rad.session_rad(vlan_id)

            #print(int_desc_output)
            host_desc = aux_fct.get_hostname_desc(int_desc_output)
            self.ports_host_dict[mpls_int] = host_desc
            self.verification += '---\n'
            self.verification += '' + mpls_int + '\t\t' + host_desc + '\n'

            print(Cs.OKBLUE + "[+]{} Check on {}{} done".format(Cs.ENDC, self.hostname, Cs.OKGREEN) + Cs.ENDC)
            for mpls_ip in port_ip_status[1]:
                if mpls_ip != None:
                    # Get the hostname from cross connection address
                    mpls_host = aux_fct.get_hostname_from_ip(mpls_ip, hosts_list)
                    self.ports_host_dict[mpls_int + '.' + vlan_id] = mpls_host
                    self.hosts_ip_dict[mpls_host] = mpls_ip
                    self.verification += mpls_ip + '\t' + mpls_host + '\n'
                    # Recursion start here
                    if mpls_ip not in visited_nodes:
                        #self.left = Node(mpls_ip, mpls_host)
                        #self.left.session_A_cisco(vlan_id)
                        mpls_nodes.append(mpls_ip)
        #DEBUG print(self.ports_host_dict)
        #DEBUG print(self.hosts_ip_dict)
        # End session !
        s.terminate()

    def session_rad(self, vlan_id):
        plate_forme2 = '172.16.128.105'
        user_pf2 = 'tibco'
        s = pxssh.pxssh()
        s.maxread = 500000
        assert(s.login(plate_forme2, user_pf2, password)), "Not connected to PF2"
        try:
            s.sendline("telnet " + self.ip_addr)
            s.expect('[Uu]ser')
            s.sendline(username_equ)
            s.expect('[Pp]assword')
            s.sendline(password)
            i = s.expect(['user','(\S+)[>#]'])
            if i == 0:
                user = input("user>")
                s.sendline(user)
                new_password = getpass.getpass()
                s.expect('[Pp]assword')
                s.sendline(new_password)
                s.expect(['(\S+)[>#]'])

            self.prompt = s.after.decode('utf-8')
            if '>' in self.prompt:
                self.session_A_cisco(vlan_id)
                return
        except:
            print('{}Error:{} could not connect to RAD {}'.format(Cs.FAIL, Cs.ENDC, self.ip_addr))
            return

        s.sendline('configure system level-info')
        s.expect('\S+#')
        re_name = r'name\s+\"(\S+)\"'
        try:
            self.hostname = re.findall(re_name, s.before.decode('utf-8'))[0]
        except:
            self.hostname = self.prompt
        print(Cs.OKBLUE + "[+]{} Connected to {}".format(Cs.ENDC, self.hostname))
        visited_nodes.append(self.ip_addr)
        visited_nodes_name.append(self.hostname)
        s.sendline('configure flow level-info')
        i = s.expect(['more..', '\S+#', pexpect.TIMEOUT], timeout=10)
        level_info = list()
        if i != 2:
            while i == 0:
                level_info += s.before.decode('utf-8').split('\r\n')
                s.sendline("")
                i = s.expect(['more..', '\S+#'])
            level_info += s.before.decode('utf-8').split('\r\n')
            my_flows = aux_fct.find_flows(level_info, vlan_id)
            # Assert 2 flows exist otherwise end session
            if len(my_flows) != 2:
                print(Cs.FAIL + "[-]{} Check on {}->{}{} failed{}".format(Cs.ENDC, self.hostname, self.ip_addr, Cs.FAIL, Cs.ENDC))
                s.terminate()
                return
            #print(my_flows)
            assert(len(my_flows) == 2), "WARNING! Funct find_flows return anything but 2 flows"
            # display each info detail flow:
            eth_all = list()
            search_eth = False
            port_info = str()
            port_show_s = ""
            verif_header = " RAD {} {} ".format(self.hostname, self.ip_addr)
            pad = aux_fct.hPad(len(verif_header))
            self.verification = "\n{} RAD {} {} {}\n\n".format('='*pad, self.hostname, self.ip_addr, '='*pad)
            info_d_out = ""
            for flow in my_flows:
                s.sendline("exit all")
                s.expect(['\S+#', pexpect.TIMEOUT], timeout=5)
                cmd = "configure flow " + flow  + " info detail"
                s.sendline(cmd)
                i = s.expect(['\S+#', 'error', pexpect.TIMEOUT])
                if i == 1:
                    s.sendline(cmd)
                    s.expect(['\S+#', pexpect.TIMEOUT], timeout=5)
                    self.verification +=s.before.decode('utf-8')
                else:
                    info_d_out = s.before.decode('utf-8')
                    self.verification += info_d_out
                if search_eth == False:
                    eth_all = aux_fct.find_port_eth(info_d_out)
            # IF speed > 100Mbps
            if aux_fct.status_speed(self.verification) == True:

                #DEBUG print("eth_all : {}".format(str(eth_all)))
                for eth in eth_all:
                    cmd = "configure port " + eth + " info detail"
                    s.sendline(cmd)
                    done = False
                    while done == False:

                        i = s.expect(["more..", '\S+#', pexpect.TIMEOUT], timeout=10)
                        port_info += s.before.decode('utf-8')
                        #DEBUG print("verification on port " + eth + "\n" + port_info)
                        if i == 0:
                            s.sendline("")
                        else:
                            s.sendline("exit all")
                            s.expect(['\S+#', pexpect.TIMEOUT], timeout=20)
                            done = True
            else:
                s.sendline("configure port")
                s.expect('\S+#')
                s.sendline("show summary")
                s.expect('\S+#')
                port_show_s = s.before.decode('utf-8')
                s.sendline("exit all")
                s.expect('\S+#')
            self.verification += port_info
            self.verification += port_show_s
            #DEBUG print(self.verification)
            print(Cs.OKBLUE + "[+]{} Check on {} {}done{}".format(Cs.ENDC, self.hostname, Cs.OKGREEN, Cs.ENDC))
        else:
            print(Cs.FAIL + "[-]{} Check on {} {}failed{}".format(Cs.ENDC, self.hostname, Cs.FAIL, Cs.ENDC))
        s.terminate()

    def session_rad_collecte(self, vlan_id):
        plate_forme2 = '172.16.128.105'
        user_pf2 = 'tibco'
        s = pxssh.pxssh()
        assert(s.login(plate_forme2, user_pf2, password)), "Not connected to PF2"
        try:
            s.sendline("telnet " + self.ip_addr)
            s.expect('[Uu]sername')
            s.sendline(username_equ)
            s.expect('[Pp]assword')
            s.sendline(password)
            s.expect('(\S+)[>#]')
            self.prompt = s.after.decode('utf-8')
            if '>' in self.prompt:
                self.session_A_cisco(vlan_id)
                return
        except:
            print('Error: could not connect to RAD {}'.format(self.ip_addr))
            sys.exit(1)
        s.sendline('configure system level-info')
        s.expect('\S+#')
        re_name = r'name\s+\"(\S+)\"'
        self.hostname = re.findall(re_name, s.before.decode('utf-8'))[0]
        print(Cs.OKBLUE + "[+]{} Connected to {} {}".format(Cs.ENDC, self.hostname, self.ip_addr))
        visited_nodes.append(self.ip_addr)
        visited_nodes_name.append(self.hostname)

        """
        for i in range(len(flow_profile)):
            s.sendline('configure flow ' + flow_profile[i] + ' info detail')
            s.expect('\S+#')
            inf_d_out = s.before.decode('utf-8')
            no_flow = bool(re.match(r"no classifier", inf_d_out))
            if no_flow == False:
                self.verification = "{} RAD {} {} {}\n".format('='*10, self.hostname, self.ip_addr, '='*10)
                self.verification += inf_d_out
                s.sendline('configure flows {} info d'.format(flow_bkb_client[i]))
                s.expect('\S+#')
                inf_d_out = s.before.decode('utf-8')
                self.verification += inf_d_out
        """
        print(Cs.OKBLUE + "[+]{} Check on {}{} done".format(Cs.ENDC, self.hostname, Cs.OKGREEN) + Cs.ENDC)

    def session_huawei(self, vlan_id):
        global CPE
        global hosts_list
        plate_forme2 = '172.16.128.105'
        username_pf2 = 'tibco'
        s = pxssh.pxssh()
        assert(s.login(plate_forme2, username_pf2, password)), "Not connected to PF2"
        #s.sendline("cat /etc/hosts")
        #s.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=10)
        #hosts_list = s.before.decode("utf-8")

        try:
            s.sendline("telnet " + self.ip_addr)
            s.expect('sername')
            s.sendline(username_equ)
            s.expect('assword')
            s.sendline(password)
            s.expect('[<]\S+[>]+')
            self.prompt = s.after.decode("utf-8")
            if self.hostname == None:
                self.hostname = self.prompt[1:-1]
            print(Cs.OKBLUE + "[+]{} Connected to {}->{}".format(Cs.ENDC, self.hostname, self.ip_addr))
        except:
            print('{}Error:{} could not connect to {} {}'.format(Cs.FAIL, Cs.ENDC, self.ip_addr, self.hostname))
            sys.exit(1)

        visited_nodes.append(self.ip_addr)
        visited_nodes_name.append(self.hostname)

        s.sendline("display mpls l2vc " + vlan_id)
        disp_mpls_out = str()

        while True:
            i = s.expect(['More', self.prompt, pexpect.TIMEOUT], timeout = 10)
            disp_mpls_out += s.before.decode("utf-8")
            if i == 0:
                s.sendline(" ")
            else:
                break
        verif_header = " {} {} ".format(self.hostname, self.ip_addr)
        pad = aux_fct.hPad(len(verif_header))
        self.verification = "\n{} {} {} {}\n\n".format('='*pad, self.hostname, self.ip_addr, '='*pad)
        #self.verification += disp_mpls_out
        if disp_mpls_out == None or disp_mpls_out == '':
            print("{}[-] {} : mpls l2vc {} not found{}".format(Cs.FAIL, self.hostname, vlan_id, Cs.ENDC))
        port, ip_dest, session_state, ac_state = aux_fct.hw_port_ip_status(disp_mpls_out)
        mpls_nodes.append(ip_dest)
        upDown =  None
        if session_state == 'up':
            upDown = Cs.OKGREEN
        else:
            upDown = Cs.FAIL
        print("[*] Session state is {}{}{}".format(upDown, session_state, Cs.ENDC))
        if ac_state == 'up':
            upDown = Cs.OKGREEN
        else:
            upDown = Cs.FAIL
        print("[*] AC state is {}{}{}".format(upDown, session_state, Cs.ENDC))

        cmd = "display interface description " + port
        s.sendline(cmd)
        s.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=5)
        disp_description = s.before.decode("utf-8").split('\r\n')[-2]
        #DEBUG print("display description: \n" + str(disp_description))
        # var sid is ServiceID-Operator-Client-@IP_CPE
        sid = aux_fct.hw_description(disp_description)
        rad_ip = aux_fct.match_ip_addr(sid)
        host_dest = aux_fct.get_hostname_from_ip(ip_dest, hosts_list)

        self.ports_host_dict[port] = sid
        self.ports_host_dict[port + '.' + vlan_id] = ip_dest + " -> " + host_dest
        self.hosts_ip_dict[ip_dest] = host_dest
        for port, host in self.ports_host_dict.items():
            self.status += "[*] " + port + ' : ' + host + '\n'
            self.verification += port + ' : ' + host + '\n\n'
        #self.verification += self.status
        self.verification += disp_mpls_out
        #IP destination 10.129.4.7 : Paris76095
        #self.status += "IP destination " + ip_dest + " : " + host_dest
        print(self.status)
        print(Cs.OKBLUE + "[+]{} Check on {}{} done".format(Cs.ENDC, self.hostname, Cs.OKGREEN) + Cs.ENDC)
        # var CPE is False if already visited
        if rad_ip != None and CPE == True:
            CPE = False
            self.rad = Node(rad_ip)
            print(Cs.OKBLUE + "[+]{} Connecting to CPE {}".format(Cs.ENDC, rad_ip))
            self.rad.session_rad(vlan_id)
        elif rad_ip != None and CPE == False:
            #FIXME compute the collecte rad session
            self.rad = Node(rad_ip)
            print(Cs.OKBLUE + "[+]{} Connecting to collecte {}".format(Cs.ENDC, rad_ip))
            self.rad.session_rad(vlan_id)


        s.terminate()


def print_level_order(head, queue = deque()):
    global CPE_VERIF
    if head is None:
        return
    if head.rad != None:
        if CPE_VERIF == True:
            print(head.rad.verification)
            print(head.status)
            print(head.verification)
            CPE_VERIF = False
        else:
            if head.isHuawei == False:
                print(head.verification)
                print(head.status)
                print(head.rad.verification)
            else:
                print(head.verification)
                print(head.rad.verification)

    else:
        print(head.verification)

    #FIXME To uncomment when collecte Rad check enable
    #if head.rad != None and CPE_VERIF == False:
    #    print(head.rad.verification)
    [queue.append(node) for node in [head.left, head.right] if node]
    if queue:
        print_level_order(queue.popleft(), queue)

if __name__ == "__main__":
    CPE = True
    CPE_VERIF = True
    username_equ = None
    IP = None
    vlan_id = None
    if len(sys.argv) >= 2:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            print("Usage: python3 Node.py <username> [IP] [VLAN]")
            sys.exit(0)
    if len(sys.argv) <= 2:
        print("Wrong usage ! python3 Nodes.py <username> [@IP] [VLAN]")
        sys.exit(1)
    for arg in sys.argv[1:]:
        if username_equ == None:
           username_equ = arg
        elif IP == None:
            IP = aux_fct.validIP(arg)
        elif vlan_id == None:
            vlan_id = aux_fct.validVlan(arg)
    # SERVICE:=True if AC else False
    SERVICE = None
    password = getpass.getpass()
    hosts_list = None
    visited_nodes = list()
    visited_nodes_name = list()
    mpls_nodes = list()
    if IP == None:
        IP = aux_fct.validIP(str(input("@IP PoP: ")))
    if vlan_id == None:
        vlan_id = aux_fct.validVlan(str(input("VLAN id: ")))
    print(Cs.HEADER + "---\n[.] LOADING..." + Cs.ENDC)
    siteA = Node(IP)
    siteA.session_A_cisco(vlan_id)
    siteB = None
    if mpls_nodes:
        siteB = Node(mpls_nodes[0])
        siteB.session_A_cisco(vlan_id)
    print("\nVisited Nodes: " + str(visited_nodes_name))
    res = input("..Press [ENTER] to continue..")
    if res:
        sys.exit(1)
    print_level_order(siteA)
    print_level_order(siteB)

