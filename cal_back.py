#! /usr/bin/python3
""" 
Powered by Masterlovsky@gmail.com Version1.0
This is a simple script to calculate the theoretical flow back to the parent node

"""
import os
import json
import sys

BYTES_PER_REQ = 16626

def get_father_output_byte(father_ip: str, father_port: int) -> int:
    if ":" not in father_ip:
        print("[WARN] father ip is not ipv6 address!")
        return 0
    fatherIP = "[" + father_ip + "]" + ":" + str(father_port)
    cmd = 'curl -g -s "http://[' + father_ip + \
        ']/stats/control?cmd=status&group=upstream@group&zone=*&group=n=nodes@group&zone=*"'
    log = {'fatherIP': fatherIP, 'fatherInbytes': 0,
           'fatherOutBytes': 0, 'localInBytes': 0, 'localOutBytes': 0}
    ss = os.popen(cmd).readlines()
    if len(ss) == 0:
        print("[ERROR] [get_father_output_byte] get empty result")
        return 0
    result = json.loads(ss[0])
    if 'upstreamZones' in result.keys():
        server = (result['upstreamZones'])['::nogroups']
        server_num = len(server)
        for i in range(server_num):
            j = server[i]
            if j['server'] == fatherIP:
                log['fatherInbytes'] = j['inBytes']
                log['fatherOutBytes'] = j['outBytes']
            else:
                log['localInBytes'] += j['inBytes']
                log['localOutBytes'] += j['outBytes']
    return int(log["fatherOutBytes"])


def get_theoretical_rc_from_file(file_A: str, file_B: str) -> int:
    """
    get the theoretical flow back from file_A to file_B
    """
    uri_set = set()
    with open(file_A, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            uri_set.add(line.strip())
    with open(file_B, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            uri_set.add(line.strip())
    print("[INFO] [get_theoretical_rc_from_file] uri_set size:", len(uri_set))
    return len(uri_set) * BYTES_PER_REQ

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 cal_back.py uri_used_file1 uri_used_file2")
        exit(1)
    fatherOutBytes = get_father_output_byte("2400:dd01:1037:8090::5", 8080)
    theoretical_Bytes = get_theoretical_rc_from_file(sys.argv[1], sys.argv[2])
    print("theoretical_Bytes: " + str(theoretical_Bytes) + " / fatherOutBytes: " + str(fatherOutBytes))
