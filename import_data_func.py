"""
    Android Malware Detection import_data file
    Author: Xinrun Zhang
    Date: 10/19/2020 13:31
"""

import os
import re


def get_dir(root_path, all_file):
    # input: a string (master path) and a list (empty, which is going to store all the file path)
    # return: a list (all the files' name under that path)
    # using a recursion to get into sub directory

    file_list = os.listdir(root_path)
    file_list.sort()

    for file_name in file_list:
        sub_path = os.path.join(root_path, file_name)
        if os.path.isdir(sub_path):
            get_dir(sub_path, all_file) # recursion
        else:
            all_file.append(sub_path)
    return all_file


def load_single_file(file_name):
    # input: a string (a path that indicate the position of the file)
    # return: a list (contains all the lines in the file)
    with open(file_name) as f:
        line = f.readline()
        line = line.strip('\n')
    return line


#def load_malicious_data(all_file):
#    # input: a list (all_file, contains all the addresses of traces)
#    # output: two lists, x_malicious (data) and y_malicious (labels)
#    pkgName = []
#    x = []
#    y = []
#    for file in all_file:
#        pkgName.append('1-'+file[126:-4])
#        x.append(load_single_file(file))
#        y.append(1)
#    return pkgName,x, y
#
#
#def load_benign_data(all_file):
#    # input: a list (all_file, contains all the addresses of traces)
#    # output: two lists, x_benign (data) and y_benign (labels)
#    pkgName = []
#    x = []
#    y = []
#    for file in all_file:
#        pkgName.append('0-'+file[123:-4])
#        x.append(load_single_file(file))
#        y.append(1)
#    return pkgName,x, y


def load_malicious_data(all_file, l):
    # input: a list (all_file, contains all the addresses of traces)
    # output: two lists, x_malicious (data) and y_malicious (labels)
    pkgName = []
    x = []
    y = []
    label = []
    
    start = 129 if l=='Train' else 128
    
    for file in all_file:
        pkgName.append(file[start:-4])
        x.append(load_single_file(file))
        y.append(1)
        label.append(l)
    return pkgName,x, y, label


def load_benign_data(all_file, l):
    # input: a list (all_file, contains all the addresses of traces)
    # output: two lists, x_benign (data) and y_benign (labels)
    pkgName = []
    x = []
    y = []
    label = []

    start = 126 if l=='Train' else 125

    for file in all_file:
        pkgName.append(file[start:-4])
        x.append(load_single_file(file))
        y.append(0)
        label.append(l)
    return pkgName,x, y, label




def select_length_over_500_traces(pkgName, x, y, l):
    # input: original system call trace x and labels y
    # output: system call trace x which contains all the traces which is longer than 500, and their labels y
    pkgName_new = []
    x_new = []
    y_new = []
    label_new = []
    length = len(x)

    # traverse each trace
    for i in range(0, length):
        if len(x[i]) >= 500:
            pkgName_new.append(pkgName[i])
            x_new.append(x[i])
            y_new.append(y[i])
            label_new.append(l[i])
    return pkgName_new, x_new, y_new, label_new


def cut_the_trace_by_window(x, window_size):
    # input: a list (trace list), an int (window size, like 100/200/300)
    # output: a list (trace list after cutting)
    x_new = []
    for trace in x:
        trace = trace.split()
        trace_len = len(trace)
        if trace_len < window_size:
            trace = ' '.join(trace)
            x_new.append(trace)
        else:
            trace = trace[:window_size]
            trace_new = ' '.join(trace)
            x_new.append(trace_new)
    return x_new