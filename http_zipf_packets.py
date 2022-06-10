#! /usr/bin/python3
from time import sleep
from pyecharts import options
from pyecharts.charts import Bar
import numpy as np
import getopt
import sys
import requests
import threading
import multiprocessing

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'
}

# ADDPORT = "" # defult request use :80/443
ADDPORT = ":8080"
SLEEPTIME = 0.1  # sleep () seconds between requests
# zipf distribution: https://en.wikipedia.org/wiki/Zipf%27s_law. We let C = 1.0


def read_uri_list(filename):
    with open(filename, 'r') as f:
        uri_list = f.read().splitlines()
    return uri_list


def generate_zipf_dist(num_flows, total_packets, power) -> list:
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

    print("[generate zipf flows] # request number in the first uri = {}".format(
        zipf_dist[0]))

    return zipf_dist


def generate_zipf_requests(dstip, num_flows, total_packets, power) -> list:
    # * get zipf dist
    zipf_dist = generate_zipf_dist(num_flows, total_packets * 10, power)

    # * check dstip is ipv6 address
    if ':' in dstip:
        dstip = '[' + dstip + ']' + ADDPORT

    # * get url list
    url_l = []

    for i in range(num_flows):
        url = "http://{}{}".format(dstip, uri_list[i])
        for j in range(zipf_dist[i]):
            url_l.append(url)

    np.random.shuffle(url_l)
    return url_l[0:total_packets]


def draw_bar(url_req_list: list):
    print("[draw bar] render html file...")
    url_l = list(set(url_req_list))
    url_l.sort(key=lambda x: url_req_list.count(x), reverse=True)
    c = (
        Bar(init_opts=options.InitOpts(width='1200px', height='720px'))
        .add_xaxis(url_l)
        .add_yaxis("RequestNumber", [url_req_list.count(url) for url in url_l])
        .set_global_opts(title_opts=options.TitleOpts(title="Request Number-URL FIGURE"),
                         xaxis_opts=options.AxisOpts(name="URL",
                                                     axislabel_opts=options.LabelOpts(rotate=-30)),
                         yaxis_opts=options.AxisOpts(name="REQ Number"),
                         datazoom_opts=options.DataZoomOpts(
                             range_start=0, range_end=100, type_="inside"),
                         )
    )
    c.render("result.html")
    return c


def send_request(url_list: list):
    global succ_msg_num
    for url in url_list:
        try:
            print("[{}] Get: {}".format(threading.current_thread().name, url))
            r = requests.get(url, headers=headers, timeout=1)
            lock.acquire()
            if r.status_code == 200:
                succ_msg_num += 1
            else:
                print(r)
            lock.release()
            # print("Status code: ", r.status_code)
            sleep(SLEEPTIME)
        except requests.exceptions.RequestException as e:
            print(e)


if __name__ == "__main__":
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "i:f:p:e:u:")
        if len(opts) not in (4, 5):
            print("Usage: -i <ip/domain> -f <number of flows> -p <number of packets> -e <exponent greater than 1> -u <uri_list_path>")
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
        print("Usage: -i <ip/domain> -f <number of flows> -p <total number of packets> -e <exponent greater than 1.0> -u <uri_list_path>")

    start_index = 1 # todo: [set to need value]
    uri_list = ["/gen1/{}.txt".format(i)
                for i in range(start_index, start_index + f + 1)]  # generate uri list
    if u != "":
        uri_list = read_uri_list(u)
    print("[Main] uri list len: {}, first 10 uri in uri_list: {}".format(
        len(uri_list), uri_list[0:10]))
    url_list = generate_zipf_requests(i, f, p, e)
    max_thread_num = multiprocessing.cpu_count()
    succ_msg_num = 0
    lock = threading.Lock()
    thread_list = []
    if len(url_list) < max_thread_num:
        send_request(url_list)
    else:
        for i in range(max_thread_num):
            t = threading.Thread(target=send_request, args=(
                url_list[i::max_thread_num],))
            thread_list.append(t)
            t.start()
    for t in thread_list:
        t.join()
    draw_bar(url_list)  # draw bar chart of uri request number
    print("[Main]: Number of flows = %d Number of packets = %d Zipf exponent = %f" % (f, p, e))
    print("[Main]: real flow number: {}".format(len(set(url_list))))
    print("[Main]: URL_REQ: {}".format(set(url_list)))
    print("[Main]: Total number of success requests = {}".format(succ_msg_num))
