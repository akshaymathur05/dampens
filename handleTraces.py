"""
    handle traces file
    Author: Xinrun Zhang
    Date: 08/30/2020
"""

import os
#from syscalls_arm import syscalls_arm as syscall_table


# get_file_dir function
def get_file_dir(root_path):
    # input: a string (master path)
    # return: a list (all the files' name under that path)

    file_list = os.listdir(root_path)
    file_list.sort()
    all_file = []

    for file_name in file_list:
        sub_path = os.path.join(root_path, file_name)
        all_file.append(sub_path)
    return all_file


# get_file_list function
def get_file_list(root_path):
    # input: a string
    # output: a list (file list)
    
    file_list = os.listdir(root_path)
    file_list.sort()
    all_file = []

    for file_name in file_list:
        all_file.append(file_name)
    return all_file


# get_syscall_table function
def get_syscall_table(table_dir):
    # input: a string (table path)
    # output: a dictionary
    table_dict = {}
    
    with open(table_dir, 'r') as f:
        for line in f.readlines():
            line = line.split()
            syscall_name = line[0]
            syscall_number = line[1]
            table_dict[syscall_name] = syscall_number
    return table_dict


if __name__ == "__main__":
    # initial root directory
    #log_dir = "/home/xinrun/AndroidStudioProjects/AndroidMalwareDetection/log"
    #log_dir = "C:\\Users\\amathur2\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp6\\data\\benign\\"
    #log_dir = "D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\syscalls\\benign\\"
    log_dir = "D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\syscalls\\malicious\\"

    
    
    
    traces_path_list = get_file_dir(log_dir)
    traces_name_list = get_file_list(log_dir)
    index = 0

    # initial system table directory
    # get the system call table
    table_dir = "D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\syscall_table.txt"
    syscall_table = get_syscall_table(table_dir)
    # initial modified syscall traces directory
    #aim_dir = "D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\syscalls_modified\\benign\\"
    aim_dir = "D:\\OneDrive-UT\\OneDrive - University of Toledo\\Documents\\Research\\AMD\\Phase 2\\Experiments\\Exp7\\syscalls_modified\\malicious\\"

    # handle each trace file
    for trace in traces_path_list:
        print(index, traces_name_list[index])
        saved_dir = aim_dir + traces_name_list[index] # initial dir for aim txt file
        with open(trace, 'r') as f:
            with open(saved_dir, 'w') as a: # create aim txt file
                for line in f.readlines():
                    syscall_name = line.split()[1].split('(')[0]
                    if syscall_name in syscall_table.keys():
                        syscall_num = syscall_table[syscall_name]
                        a.write(str(syscall_num) + ' ')
        index += 1