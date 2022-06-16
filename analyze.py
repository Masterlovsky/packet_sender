#! /usr/bin/python3
""" 
Powered by Masterlovsky@gmail.com Version1.0
This is a simple script to calculate the theoretical flow back to the parent node

"""
import os
import socket
import time
import json
import sys
from pyecharts import options
from pyecharts.charts import Line 

BYTES_PER_REQ = 16626 # todo: change to right value
CAL_PERIOD = 0.5  # father recall proportion calcultion Period (s)
LINE_UPDATE_INTER = 5  # father recall proportion calcultion Period (s)
LOCALHOST = "127.0.0.1"


def cfg_get_sum_bytes(file_name: str):
    sum_bytes = []
    if not os.path.exists(file_name):
        print("[WARNING] [cfg_get_sum_bytes] file not exists")
        return sum_bytes
    with open(file_name, "r") as f:
        for line in f:
            if len(sum_bytes) == 0:
                sum_bytes.append(int(line.strip().split(' ')[1]))
                continue
            sum_bytes.append(sum_bytes[-1] + int(line.strip().split(' ')[1]))
    return sum_bytes


def load_uri_summary_dict_from_json(file_name: str) -> dict:
    if not os.path.exists(file_name):
        print("[WARNING] [load_uri_summary_dict_from_json] file not exists")
        return {}
    with open(file_name, "r") as f:
        uri_summary_dict = json.load(f)
    return uri_summary_dict


def loop_thread_cal_proportion(addr_list:list, father_addr="2400:dd01:1037:8090::5", father_port=8080):
    recal_prop_list = []
    recal_prop_list.append((0,0,0))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # set socket timeout to 1s
    s.settimeout(1.0)
    break_flag = 0
    while True:
        total_send_bytes = 0
        send_pkts = 0
        time.sleep(CAL_PERIOD)
        father_out_bytes, local_out_bytes = get_output_bytes(father_addr, father_port)
        try:
            for i, addr in enumerate(addr_list):
                s.sendto(bytes.fromhex("01"), addr)
                recv_msg, _ = s.recvfrom(1024)
                send_pkts = int(bytes.hex(recv_msg), 16)
                if uri_summary_dict != None:
                    total_send_bytes += sum_bytes_list[i][send_pkts]
                else:
                    total_send_bytes += int(bytes.hex(recv_msg), 16) * BYTES_PER_REQ
            print("[INFO] total_send_packets:", send_pkts, " / total_send_bytes:", total_send_bytes)
            break_flag = 0
        except socket.timeout:
            print("[WARN] [loop_thread_cal_proportion] socket timeout")
            break_flag += 1
            if break_flag > 5:
                print("[ERROR] [loop_thread_cal_proportion] socket timeout too many times")
                break
            continue
        if recv_msg and father_out_bytes > 0:
            recal_prop_list.append((total_send_bytes, father_out_bytes, local_out_bytes))
        if len(recal_prop_list) % LINE_UPDATE_INTER == 0:
            draw_line_chart(recal_prop_list)
            print("[update line chart] render html file...")


def get_output_bytes(father_ip: str, father_port: int):
    if ":" not in father_ip:
        print("[WARN] father ip is not ipv6 address!")
        return 0, 0
    fatherIP = "[" + father_ip + "]" + ":" + str(father_port)
    cmd = 'curl -g -s "http://[' + father_ip + \
        ']/stats/control?cmd=status&group=upstream@group&zone=*&group=n=nodes@group&zone=*"'
    log = {'fatherIP': fatherIP, 'fatherInbytes': 0,
           'fatherOutBytes': 0, 'localInBytes': 0, 'localOutBytes': 0}
    ss = os.popen(cmd).readlines()
    if len(ss) == 0:
        print("[ERROR] [get_father_output_byte] get empty result")
        return 0, 0
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
    return int(log["fatherOutBytes"]), int(log["localOutBytes"])


def get_theoretical_rc_from_files(uri_summary_dict: dict, *files):
    """
    get the theoretical flow back from files
    """
    def get_set_from_file(file_name: str, uri_set: set):
        with open(file_name, "r") as f:
            for line in f:
                uri_set.add(line.strip().split(' ')[0])

    all_set = [set() for i in range(len(files))]
    for i in range(len(files)):
        get_set_from_file(files[i], all_set[i])
        print("[INFO] [get_theoretical_rc_from_file] uri_set{} size:{}".format(i, len(all_set[i])))
    union_set = set.union(*all_set)
    intersection_set = set.intersection(*all_set)
    print("[INFO] [get_theoretical_rc_from_files] union_set size:{}, intersection_set size:{}".format(
        len(union_set), len(intersection_set)))
    if uri_summary_dict is None:
        return len(union_set) * BYTES_PER_REQ, len(intersection_set) * BYTES_PER_REQ
    union_bytes = 0
    intersection_bytes = 0
    for uri in union_set:
        union_bytes += uri_summary_dict[uri][0]
    for uri in intersection_set:
        intersection_bytes += uri_summary_dict[uri][0]
    return union_bytes, intersection_bytes


def draw_line_chart(recal_prop_list: list):
    l = (
        Line(init_opts=options.InitOpts(width='1280px', height='720px'))
        .add_xaxis(xaxis_data=["{}".format(i) for i in range(len(recal_prop_list))])
        .add_yaxis(
            series_name="send_bytes",
            y_axis=[i[0] for i in recal_prop_list],
            symbol="rect",
            color="blue",
            label_opts=options.LabelOpts(is_show=True),
        )
        .add_yaxis(
            series_name="father_recall_bytes",
            y_axis=[i[1] for i in recal_prop_list],
            symbol="triangle",
            color="green",
            label_opts=options.LabelOpts(is_show=True),
        )
        .add_yaxis(
            series_name="local_recall_bytes",
            y_axis=[i[2] for i in recal_prop_list],
            symbol="circle",
            color="red",
            label_opts=options.LabelOpts(is_show=True),
        )
        .extend_axis(
            yaxis=options.AxisOpts(type_="value",
            axistick_opts=options.AxisTickOpts(is_show=True),
            splitline_opts=options.SplitLineOpts(is_show=True),)
        )
        .set_global_opts(
            title_opts=options.TitleOpts(title="Traffic statistics Figure"),
            tooltip_opts=options.TooltipOpts(is_show=True, trigger="axis"),
            xaxis_opts=options.AxisOpts(
                type_="value", name="Time*{}s".format(LINE_UPDATE_INTER*CAL_PERIOD)),
            yaxis_opts=options.AxisOpts(
                type_="value", name="Traffic (Bytes)",
                axistick_opts=options.AxisTickOpts(is_show=True),
                splitline_opts=options.SplitLineOpts(is_show=True),
            ),
            datazoom_opts=options.DataZoomOpts(
                range_start=0, range_end=100, type_="inside"),
        )
    )

    l2 = (
        Line(init_opts=options.InitOpts(width='1280px', height='720px'))
        .add_xaxis(xaxis_data=["{}".format(i) for i in range(len(recal_prop_list))])
        .add_yaxis(
            series_name="father_recall_proportion",
            y_axis=[round(i[1] / i[0], 3) for i in recal_prop_list if i[0] != 0],
            yaxis_index = 1,
            symbol="emptyCircle",
            color="pink",
            linestyle_opts=options.LineStyleOpts(type_="dashed", width=2),
        )
    )
    l.overlap(l2)
    l.render("./result_output/result_traffic.html")
    return l


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cal_back.py uri_used_file1 uri_used_file2 ...")
        exit(1)
    addr_list = [(LOCALHOST, 22333), (LOCALHOST, 22334)] #! change to real ip address and port
    cfg_list = ["uri_list0.cfg", "uri_list1.cfg"] #! change to real cfg_file names generated by log_analyzer.py
    uri_summary_dict = load_uri_summary_dict_from_json("uri_summary.json") #! change to real json file name
    sum_bytes_list = [cfg_get_sum_bytes(s) for s in cfg_list]
    loop_thread_cal_proportion(addr_list)
    fob, lob = get_output_bytes("2400:dd01:1037:8090::5", 8080)
    union_Bytes_t, intersection_Bytes_t = get_theoretical_rc_from_files(uri_summary_dict, sys.argv[1], sys.argv[2])
    print("[theoretical] Union_Bytes: " + str(union_Bytes_t) + ", intersection_Bytes: " + str(intersection_Bytes_t))
    print("[Actrual] fatherOutBytes: " + str(fob) + " / localOutBytes: " + str(lob))
