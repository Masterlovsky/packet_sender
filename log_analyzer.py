#! /usr/bin/python3
import time
import os
import sys
import json

DATE_TIME_FORMAT = "%d/%b/%Y:%X"
TIME_INTERVAL = 60 * 60 # (s)

class ShowProcess(object):
    """
    Class that displays processing progress
    The processing progress can be displayed by calling related functions of this class
    """

    def __init__(self, max_steps):
        self.max_steps = max_steps
        self.max_arrow = 50
        self.i = 0  # Current processing progress

    def show_process(self, i=None):
        if i is not None:
            self.i = i
        num_arrow = int(self.i * self.max_arrow / self.max_steps)
        num_line = self.max_arrow - num_arrow
        percent = self.i * 100.0 / self.max_steps
        process_bar = '\r' + '[' + '>' * num_arrow + \
            '-' * num_line + ']' + '%.2f' % percent + '%'
        sys.stdout.write(process_bar)
        sys.stdout.flush()
        self.i += 1

    def close(self, words='done'):
        print('')
        print(words)
        self.i = 1


def analyze_log_file(log_file, cluster_num):
    '''
    analyze log file, generate uri_dict and uri_list.cfg
    '''
    uri_dict = {}
    client_dict = {}
    line_num = 0
    cluster_idx = 0
    cfg_file_list = []
    for i in range(cluster_num):
        f = open("uri_list{}.cfg".format(i), 'w')
        cfg_file_list.append(f)
    with open(log_file, 'r') as f:
        for line in f:
            if line_num % 10000 == 0:
                print("[INFO] Already read %d lines..." % line_num)
            if line_num >= 500000:
                break
            # todo: skip not-http-Get requests
            items = line.split()
            if len(items) < 6:
                continue
            if items[5] != '"GET':
                continue
            line_num += 1
            # get time, check if it is valid =================================
            # recv_time_str = items[4][1:]
            # recv_t = time.strptime(recv_time_str, DATE_TIME_FORMAT)
            # if abs(time.mktime(recv_t) - time.mktime(standard_time)) > TIME_INTERVAL / 2:
            #     continue
            # get uri =========================================================
            url = items[6]
            if "?" in url:
                url = url.split("?")[0]
            uri = "/" + "/".join(url.split('/')[3:])
            # get client ip ===================================================
            client_ip = items[0]
            # put uri into right cluster cfg file 
            if client_ip in client_dict:
                c_idx = client_dict[client_ip]
            else:
                c_idx = cluster_idx % cluster_num
                client_dict[client_ip] = c_idx
                cluster_idx += 1
            # get file byte size ==============================================
            file_size = items[9]
            cfg_file_list[c_idx].write(uri + " " + file_size + "\n")
            if uri not in uri_dict:
                # (file bytes, count)
                uri_dict[uri] = [int(file_size), 1]
            else:
                uri_dict[uri][1] += 1
    print("[INFO] Get uri_dict from log_file: %s done!" % log_file)
    for f in cfg_file_list:
        f.close()
    print("[INFO] Generate {} uri_config files done!".format(cluster_num))
    return uri_dict, line_num


def generate_cache_files(uri_dict, cache_root_path):
    '''
    generate cache files from uri_dict
    '''
    bar = ShowProcess(len(uri_dict) - 1)
    if cache_root_path[-1] == '/':
        cache_root_path = cache_root_path[:-1]
    for uri in uri_dict.keys():
        bar.show_process()
        path = cache_root_path + "/".join(uri.split('/')[:-1]) + "/"
        os.popen("mkdir -p %s" % path)
        file_size = uri_dict[uri][0]
        os.popen("dd if=/dev/urandom of=" + cache_root_path +
                 uri + " bs=" + str(file_size) + " count=1 2>/dev/null")
    bar.close("[INFO] Generate cache files from uri_dict done!")


def gen_uri_summary_file(uri_dict, cfg_file):
    '''
    generate uri_summary.json file from uri_dict
    '''
    with open(cfg_file, 'w') as f:
        json.dump(uri_dict, f)
    print("[INFO] Generate uri_summary.json file done!")


if __name__ == "__main__":
    standard_time = time.strptime('09/Jun/2022:22:22:09', DATE_TIME_FORMAT) # todo: change to correct time
    if len(sys.argv) != 3:
        print("[ERROR] Usage: %s log_file cache_root_path" % sys.argv[0])
        exit(1)
    uri_dict, line_number = analyze_log_file(sys.argv[1], 2) # 2 is cluster_num
    print("[INFO] Record number: {} / URI total number: {}".format(line_number, len(uri_dict)))
    generate_cache_files(uri_dict, sys.argv[2])
    gen_uri_summary_file(uri_dict, "uri_summary.json")
