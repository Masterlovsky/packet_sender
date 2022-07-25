#! /usr/bin/python3
""" 
Powered by Masterlovsky@gmail.com Version1.0
This is a simple example of using zipf-like distribution to generate http get requests.
The distribution is based on the number of flows and the total number of packets.
# zipf distribution: https://en.wikipedia.org/wiki/Zipf%27s_law. We let C = 1.0

"""
import time
import re
import socket
import getopt
import sys
import os
import json
import requests
import threading
import logging
import yaml
import multiprocessing
from pyecharts import options
from pyecharts.charts import Bar, Line
import numpy as np

BYTES_PER_REQ = 16626  # todo: change to right value

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36',
    'Connection':'close'
}



def udp_socket_listener(dstip="127.0.0.1", dstport=22333):
    global loop_flag
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((dstip, dstport))
    while True:
        msg, addr = s.recvfrom(1024)
        logger.debug('[Socket] Message from [%s:%s]: %s' %(addr[0], addr[1], bytes.hex(msg)))
        if bytes.hex(msg) == "01":
            # lock.acquire()
            s.sendto(send_msg_num.to_bytes(4, "big"), addr)
            logger.debug('[Socket] Message send to [%s:%s]: %s' %(addr[0], addr[1], hex(send_msg_num)))
            # lock.release()
        elif bytes.hex(msg) == "02":
            # set loop_flag to False
            s.sendto(bytes.fromhex("01"), addr)
            logger.info("[Socket] Receive stop signal from [%s:%s]" %(addr[0], addr[1]))
            loop_flag = False
        else:
            logger.warn("Unsupported message, {}".format(bytes.hex(msg)))


def log_init(log_level="INFO") -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(level="DEBUG")
    console = logging.StreamHandler()
    console.setLevel(log_level)
    logger.addHandler(console)
    handler = logging.FileHandler("log.txt")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '[%(asctime)s]-[%(threadName)s]-[%(levelname)s]: %(message)s')
    handler.setFormatter(formatter)
    console.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def read_conf_yml(filename: str = "conf.yaml") -> dict:
    with open(filename, 'r') as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)
    return cfg


def read_uri_cfg(dstip, filename, start_index=0, total_packets=0, prefix='/gen') -> list:
    url_l = []
    i = 0
    with open(filename, 'r') as f:
        for line in f:
            uri = line.strip().split(' ')[0]
            if uri.startswith(prefix):
                uri = uri.replace(prefix, "", 1)
            if i % 50000 == 0:
                logger.debug("[CFG] Already read {} lines".format(i))
            url = "http://{}{}{}".format(dstip, prefix, uri)
            url_l.append(url)
            i += 1
    logger.info("[CFG] read_uri_cfg done!")
    send_max_num = len(url_l) - start_index if total_packets == 0 else total_packets
    return url_l[start_index:start_index + send_max_num]


def read_uri_json(dstip, filename, total_packets=0) -> list:
    url_l = []
    with open(filename, 'r') as f:
        uri_dict = json.load(f)
        for uri in uri_dict.keys():
            url = "http://{}{}".format(dstip, uri)
            for _ in range(uri_dict[uri][1]):
                url_l.append(url)
    np.random.seed(RANDOM_SEED)
    np.random.shuffle(url_l)
    send_max_num = len(url_l) if total_packets == 0 else total_packets
    return url_l[0:send_max_num]


def dump_uri_sent_list(uri_sent_list, filename):
    with open(filename, 'w') as f:
        for uri in uri_sent_list:
            # todo: change to real size
            f.write(uri + " " + str(BYTES_PER_REQ) + '\n')


def _generate_zipf_p_l(num_flows, power) -> list:
    '''
    Calculate the Zipf probability distribution for each URI
    '''
    summation = 0
    res = 0
    zipf_p_l = []
    # * fill zipf probability list
    for i in range(1, num_flows+1):
        summation += 1.0 / i**power
    C = 1.0 / summation
    for i in range(1, num_flows+1):
        res = C / i**power
        zipf_p_l.append(res)
    return zipf_p_l


def _generate_zipf_dist(num_flows, total_packets, power) -> list:
    summation = 0
    res = 0
    zipf_dist = []
    # * fill zipf dist
    for i in range(1, num_flows+1):
        summation += 1.0/i**power

    init_num_packets = total_packets/summation
    for i in range(1, num_flows + 1):
        res = init_num_packets * (1.0/i**power)
        zipf_dist.append(int(res))

    if sum(zipf_dist) != total_packets:
        zipf_dist[0] += total_packets-sum(zipf_dist)

    logger.info("[generate zipf flows] # request number in the first uri = {}".format(
        zipf_dist[0]))

    return zipf_dist


def generate_zipf_requests(dstip, num_flows, total_packets, power) -> list:
    # * get zipf probability list
    zipf_p_l = _generate_zipf_p_l(num_flows, power)

    # * get url list
    url_l = []

    for i in range(total_packets):
        uri = np.random.choice(uri_list, 1, p=zipf_p_l)[0]
        url = "http://{}{}".format(dstip, uri)
        url_l.append(url)

    return url_l


def generate_union_requests(dstip, num_flows, total_packets) -> list:
    # * get url list
    url_l = []
    for i in range(num_flows):
        if i < len(uri_list):
            url = "http://{}{}".format(dstip, uri_list[i])
            url_l.append(url)
    return url_l[0:total_packets]


def draw_bar(url_req_list: list, cfg: dict):
    logger.info("[draw bar] render html file...")
    url_l = list(set(url_req_list))
    url_l.sort(key=lambda x: url_req_list.count(x), reverse=True)
    url_count_l = [url_req_list.count(url) for url in url_l]
    c = (
        Bar(init_opts=options.InitOpts(width=cfg["WIDTH"], height=cfg["HEIGHT"]))
        .add_xaxis(url_l)
        .add_yaxis("RequestNumber", url_count_l)
        .set_global_opts(title_opts=options.TitleOpts(title="Request Number-URL FIGURE"),
                         xaxis_opts=options.AxisOpts(name="URL",
                                                     axislabel_opts=options.LabelOpts(rotate=15)),
                         yaxis_opts=options.AxisOpts(name="REQ Number"),
                         datazoom_opts=options.DataZoomOpts(
                             range_start=0, range_end=100, type_="inside"),
                         )
    )
    c.render(cfg["SAVE_PATH"])
    return c


def draw_line_chart(recal_prop_list: list):
    l = (
        Line(init_opts=options.InitOpts(width='1280px', height='720px'))
        .add_xaxis(xaxis_data=["{}".format(i) for i in range(len(recal_prop_list))])
        .add_yaxis(
            series_name="",
            y_axis=recal_prop_list,
            symbol="emptyCircle",
            is_symbol_show=True,
            label_opts=options.LabelOpts(is_show=True),
        )
        .set_global_opts(
            title_opts=options.TitleOpts(title="Recall Proportion FIGURE"),
            tooltip_opts=options.TooltipOpts(is_show=True, trigger="axis"),
            xaxis_opts=options.AxisOpts(
                type_="value", name="Time*{}s".format(LINE_UPDATE_INTER*CAL_PERIOD)),
            yaxis_opts=options.AxisOpts(
                type_="value", name="Recall Proportion",
                axistick_opts=options.AxisTickOpts(is_show=True),
                splitline_opts=options.SplitLineOpts(is_show=True),
            ),
            datazoom_opts=options.DataZoomOpts(
                range_start=0, range_end=100, type_="inside"),
        )
    )
    l.render("./result_output/result_recall_porp.html")
    return l


def send_request(url_list: list):
    global succ_msg_num
    global send_msg_num
    for url in url_list:
        try:
            logger.debug("[{}] Get: {}".format(
                threading.current_thread().name, url))
            r = requests.get(url, headers=headers, timeout=1)
            lock.acquire()
            send_msg_num += 1
            if send_msg_num % 200 == 0:
                logger.info("Already send {} requests".format(send_msg_num))
            if r.status_code == 200:
                succ_msg_num += 1
            else:
                logger.debug(r)
            lock.release()
            time.sleep(SEND_REQ_INTERVAL)
        except requests.exceptions.RequestException as e:
            logger.debug(e)


def request_loop(dstip, num_flows, power):
    '''
    Send requests in the loop mode, choose uri use possiblity distribution list
    '''
    print("[Main] ================ Use loop mode! =================")

    zipf_p_l = _generate_zipf_p_l(num_flows, power)


    def thread_loop():
        global send_msg_num
        global succ_msg_num
        global flow_sent_set
        global flow_sent_list
        global loop_flag
        while True:
            if loop_flag == False:
                break
            uri = np.random.choice(uri_list, 1, p=zipf_p_l)[0]
            url = "http://{}{}".format(dstip, uri)
            try:
                logger.debug("[{}] Get: {}".format(
                    threading.current_thread().name, url))
                r = requests.get(url, headers=headers, timeout=1)
                lock.acquire()
                send_msg_num += 1
                flow_sent_set.add(uri)
                flow_sent_list.append(uri)
                if len(flow_sent_set) >= num_flows:
                    loop_flag = False
                if send_msg_num % 200 == 0:
                    logger.info("Already send {} requests, uri_set_len: {}".format(
                        send_msg_num, len(flow_sent_set)))
                if r.status_code == 200:
                    succ_msg_num += 1
                else:
                    logger.debug(r)
                lock.release()
                time.sleep(SEND_REQ_INTERVAL)
            except requests.exceptions.RequestException as e:
                logger.debug(e)

    for i in range(max_thread_num):
        t = threading.Thread(target=thread_loop)
        thread_list.append(t)
        t.start()

def cal_proportion(father_addr, father_port, rc_l: list):
    BYTES_PER_REQ = 16626  # todo: change to right value
    global send_msg_num
    father_out_bytes, local_out_bytes = get_father_output_byte(father_addr, father_port)
    # father_out_byte = BYTES_PER_REQ * 0.321 # test
    recall_prop = father_out_bytes / (send_msg_num * BYTES_PER_REQ)
    rc_l.append(round(recall_prop, 3))
    logger.info("recall_prop = {:.2%}".format(recall_prop))


def loop_thread_cal_proportion(father_addr="2400:dd01:1037:8090::5", father_port=8080):
    recal_prop_list = []
    while True:
        time.sleep(CAL_PERIOD)
        cal_proportion(father_addr, father_port, recal_prop_list)
        if len(recal_prop_list) % LINE_UPDATE_INTER == 0:
            draw_line_chart(recal_prop_list)
            logger.info("[update line chart] render html file...")


def get_father_output_byte(father_ip: str, father_port: int):
    if ":" not in father_ip:
        logger.warn("father ip is not ipv6 address!")
        return (0, 0)
    fatherIP = "[" + father_ip + "]" + ":" + str(father_port)
    cmd = 'curl -g -s "http://[' + father_ip + \
        ']/stats/control?cmd=status&group=upstream@group&zone=*&group=n=nodes@group&zone=*"'
    log = {'fatherIP': fatherIP, 'fatherInbytes': 0,
           'fatherOutBytes': 0, 'localInBytes': 0, 'localOutBytes': 0}
    ss = os.popen(cmd).readlines()
    if len(ss) == 0:
        logger.error("[get_output_byte] get empty result")
        return (0, 0)
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


def param_check(argv):
    try:
        opts, args = getopt.getopt(argv, "i:f:p:e:u:")
        if len(opts) not in (4, 5):
            print("Usage: -i <ip/domain> -f <number of flows> -p <number of packets> -e <exponent> -u <uri_list_path>")
            sys.exit(1)
        u = ""
        for opt, arg in opts:
            if opt == '-i':
                i = arg
            if opt == '-f':
                f = int(arg)
            if opt == '-p':
                p = int(arg)
            if opt == '-e':
                e = float(arg)
            if opt == '-u':
                u = arg
    except getopt.GetoptError:
        print("Usage: -i <ip/domain> -f <number of flows> -p <total number of packets> -e <exponent> -u <uri_list_path>")
        exit(1)
    return i, f, p, e, u


def generate_uri_list(prefix: str, suffix: str, flows_num: int, start_index: int = 0) -> list:
    uri_list = []
    for i in range(start_index, flows_num + 1):
        if len(prefix) == 0 or prefix[-1] != '/':
            prefix += '/'
        uri_list.append(prefix + str(i) + suffix)
    return uri_list


def record_used_uri(url_requests: list, file_name: str = "used_uri.txt"):
    with open(file_name, "w") as f:
        url_l = list(set(url_requests))
        url_l.sort(key=lambda x: url_requests.count(x), reverse=True)
        for url in url_l:
            uri = "/" + "/".join(url.split("/")[3:])
            count = url_requests.count(url)
            f.write(uri + " " + str(count) + "\n")


def get_real_ip_address(ip_str: str) -> str:
    # if ip_str is ipv4 address, return ip_address + port
    if "." in ip_str and ":" in ip_str:
        # like 192.168.0.1:8080
        return ip_str
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_str):
        return ip_str + ":" + str(ADDPORT)
    # if ip_str is ipv6 address, return ipv6 address + port
    if ":" in ip_str and "[" not in ip_str:
        return "[" + ip_str + "]:" + str(ADDPORT)
    else:
        return ip_str


if __name__ == "__main__":
    # * ============= read configure file ================
    cfg = read_conf_yml() # todo: set config file path
    ADDPORT = cfg["PORT"]  
    SEND_REQ_INTERVAL = cfg["SEND_REQ_INTERVAL"]
    CAL_PERIOD = cfg["CAL_PERIOD"]
    LINE_UPDATE_INTER = cfg["LINE_UPDATE_INTER"]  
    RANDOM_SEED = cfg["RANDOM_SEED"]
    LOCALHOST = cfg["DAEMONTHREAD"]["HOST"]
    LOCALPORT = cfg["DAEMONTHREAD"]["PORT"]
    LOOP_MODE = cfg["LOOP_MODE"]  # if True, the program will loop forever until receive a signal to stop
    start_index = cfg["START_IDX"] 
    PREFIX = cfg["PREFIX"]
    SUFFIX = cfg["SUFFIX"]
    RECORD_PATH = cfg["RECORD_USED_URI_PATH"]
    # * =========== read command line arguments and initilize variables =============
    argv = sys.argv[1:]
    i, f, p, e, u = param_check(argv)
    i = get_real_ip_address(i)
    logger = log_init()
    max_thread_num = multiprocessing.cpu_count()
    send_msg_num = 0
    succ_msg_num = 0
    # * =========== main =============
    uri_list = generate_uri_list(PREFIX, SUFFIX, f, start_index)  # todo: [set prefix and suffix]
    if u != "":
        url_requests = read_uri_cfg(i, u, 0, p, PREFIX)  # todo: [set prefix]
        LOOP_MODE = False
    else:
        logger.info("uri list len: {}, first 10 uri in uri_list: {}".format(len(uri_list), uri_list[0:10]))
        url_requests = generate_zipf_requests(i, f, p, e)
    # deamon_thread = threading.Thread(name="DaemonThread", target=loop_thread_cal_proportion, daemon=True)
    deamon_thread = threading.Thread(name="DaemonThread", target=udp_socket_listener, args=(LOCALHOST, LOCALPORT,), daemon=True)
    deamon_thread.start()
    lock = threading.Lock()
    thread_list = []
    if LOOP_MODE:
        loop_flag = True
        flow_sent_set = set() # record the uri set that has been sent
        flow_sent_list = [] # record the uri list that has been sent
        request_loop(i, f, e)
        for t in thread_list:
            t.join()
        dump_uri_sent_list(flow_sent_list, "uri_list.txt")
        draw_bar(flow_sent_list)  # draw bar chart of uri request number
        record_used_uri(flow_sent_list, "./result_output/used_uri.txt")  # record used uri
        logger.info("Real URI number = {}".format(len(flow_sent_set)))
        logger.info("Number of flows = %d Number of packets = %d Zipf exponent = %f" % (f, p, e))
        logger.info("Total send requests = {}, total success requests = {}".format(send_msg_num, succ_msg_num))
        exit(0)
    if len(url_requests) < max_thread_num:
        send_request(url_requests)
    else:
        for i in range(max_thread_num):
            t = threading.Thread(target=send_request, args=(url_requests[i::max_thread_num],))
            thread_list.append(t)
            t.start()
    for t in thread_list:
        t.join()
    draw_bar(url_requests, cfg)  # draw bar chart of uri request number
    record_used_uri(url_requests, RECORD_PATH)  # record used uri
    logger.debug("URL_REQ: {}".format(set(url_requests)))
    logger.info("Number of flows = %d Number of packets = %d Zipf exponent = %f" % (f, p, e))
    logger.info("Real URI number = {}".format(len(set(url_requests))))
    logger.info("Total Send request number = {}".format(send_msg_num))
    logger.info("Total number of success requests = {}".format(succ_msg_num))
