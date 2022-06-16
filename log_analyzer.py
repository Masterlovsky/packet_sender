#! /usr/bin/python3
import os
import sys
import json


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


def get_uri_dict(log_file):
    '''
    get uri_dict from log_file
    '''
    uri_dict = {}
    with open(log_file, 'r') as f:
        for line in f:
            url = line.split(" ")[6]
            if "?" in url:
                url = url.split("?")[0]
            uri = "/" + "/".join(url.split('/')[3:])
            if uri not in uri_dict:
                # (file bytes, count)
                uri_dict[uri] = [int(line.split()[9]), 1]
            else:
                uri_dict[uri][1] += 1
    print("[INFO] Get uri_dict from log_file: %s done!" % log_file)
    return uri_dict


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


if __name__ == "__main__":
    uri_dict = get_uri_dict("test.log")
    print(uri_dict)
    generate_cache_files(uri_dict, "gen")
