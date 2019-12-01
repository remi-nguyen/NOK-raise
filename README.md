# NOK-raise

A terminal app that automates tasks on network devices like routers, switches and network termination equipments (NTE).
The script executes commands on devices, data are extraced and processed in order to find the neighboring devices.

Various information are displayed in the running time, as below.

![App demo](Resc/demo_nok.gif)

### Usage example

The script is executed in a terminal with three parameters `username` `IP_address` `Vlan_ID`

```sh
42sh$ python3 Node.py user1 10.170.1.2 2626
```
The script will output the STP/MPLS status and the flows configuration:

[View the whole output](Annex/check_done_10.170.1.2_2626.txt)

### Notable features

* Automating test on routers, switches, NTE from CISCO, HUAWEI, RAD
* If login failed on a device, you can try with different login and password
* Configuration errors are raised
   * `WARNING! VLAN <Vlan_ID> does not exist on <Hostname>`
   * `WARNING! No flow related to vlan <Vlan_ID> found on the Rad`
   * `Check on <Hostname> -> <IP@> failed`
* Showing the output of spanning-tree (STP) and MPLS commands executed on each devices where the VLAN is configured.
* Showing information about hostname, interface, destination IP address

```sh
====================== HotelTechnologies-4507 10.170.1.2 ======================
 
show spanning-tree vlan 2626

[...]

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Fa7/27              Desg FWD 19        128.411  P2p
Po1                 Desg FWD 4         128.641  P2p
Po2                 Desg FWD 20        128.642  P2p
 
Fa7/27          AC005825-PROJET3_LINKT-DUNKERQUE_PARE_BRISE-10.170.6.121
port-c1         HotelTechno-7609
port-c2         Loon-7609
```

```sh
============================ Loon-7609 10.129.1.82 ============================
 
show mpls l2transport vc 2626
 
Local intf     Local circuit              Dest address    VC ID      Status
-------------  -------------------------- --------------- ---------- ----------
Po1.2626       Eth VLAN 2626              10.129.1.25     2626       DOWN
---
port-c1         HotelTechnologies-4507
10.129.1.25     75TH2-X8A-1
```

### What I learned

* Connecting to devices via SSH and Telnet using Pexpect and Python 3
* Processing data with Regex
* Data structures
  * Linked list
  * Queue
  * Stack
  * Binary Tree
  
### Author

* **Rémi Nguyen**
