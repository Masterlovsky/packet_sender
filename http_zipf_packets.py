from time import sleep
import numpy as np
import getopt
import sys
import requests
import threading
import multiprocessing

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'
}
# zipf distribution: https://en.wikipedia.org/wiki/Zipf%27s_law. We let C = 1.0


def generate_zipf_requests(dstip, num_flows, total_packets, power) -> list:
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

    print("[generate zipf flows] # request number in the first uri = {}".format(
        zipf_dist[0]))

    # * check dstip is ipv6 address
    if ':' in dstip:
        dstip = '[' + dstip + ']'
        
    # * get url list
    url_l = []

    for i in range(num_flows):
        url = "http://{}{}".format(dstip, uri_list[i])
        for j in range(zipf_dist[i]):
            url_l.append(url)

    np.random.shuffle(url_l)
    return url_l


def send_request(url_list: list):
    for url in url_list:
        try:
            print("[{}] Get: {}".format(threading.current_thread().name, url))
            r = requests.get(url, headers=headers, timeout=1)
            # print("Status code: ", r.status_code)
            sleep(0.1)
        except requests.exceptions.RequestException as e:
            print(e)


if __name__ == "__main__":
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "i:f:p:e:")
        if len(opts) != 4:
            print(
                "Usage: -i <ip/domain> -f <number of flows> -p <number of packets> -e <exponent greater than 1>")
            sys.exit(1)
        for opt, arg in opts:
            if opt == '-i':
                i = arg
            if opt == '-f':
                f = int(arg)
            if opt == '-p':
                p = int(arg)
            if opt == '-e':
                e = float(arg)
        print("Main: Number of flows = %d Number of packets = %d Zipf exponent = %f" % (
            f, p, e))
        # uri_list = ["/{}.txt".format(i) for i in range(1, f + 1)]  # generate uri list
        uri_list = ["/s?wd={}".format(i)
                    for i in range(1, 100)]  # generate uri list
        url_list = generate_zipf_requests(i, f, p, e)
        max_thread_num = multiprocessing.cpu_count()
        if len(url_list) < max_thread_num:
            send_request(url_list)
        else:
            for i in range(max_thread_num):
                t = threading.Thread(target=send_request, args=(url_list[i::max_thread_num],))
                t.start()


    except getopt.GetoptError:
        print("Usage: -i <ip/domain> -f <number of flows> -p <total number of packets> -e <exponent greater than 1.0>")
