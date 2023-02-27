#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Sep 11 12:48:18 2022

@author: akshay
"""


import pandas as pd
import os, subprocess
from time import sleep
from androguard.core.bytecodes.apk import APK
from core import PERMISSIONS


#The benign or malicious app source
file_path="/media/akshay/CSTARBackup/amd_data/"

#Path to file constaining the names of apps and their package names
df = pd.read_csv("amd_Internet_App_Package.csv")

#Separating apk names and pkg names     
apk = list(df['App_Name'])
pkg = list(df['Pkg_Name'])

#Folder names for benign and malicious files
b_or_m = ["/benign", "/malicious"]

#Device names for real device and emulator. Make changes if they are different for you
phone = "28a1188b"
emulator = "192.168.56.102:5555"




#Directory path names to save benign and malicious pcaps
pcaps_dir_path = os.getcwd() + '/pcaps'
benign_pcaps_dir_path = pcaps_dir_path + b_or_m[0]
malicious_pcaps_dir_path = pcaps_dir_path + b_or_m[1]

#Create paths if they don't already exist. If they exist, these commands do nothing.
os.makedirs(pcaps_dir_path, exist_ok = True)
os.makedirs(benign_pcaps_dir_path, exist_ok = True)
os.makedirs(malicious_pcaps_dir_path, exist_ok = True)

#Creating the column names for permissions csv
perms_columns = [] * (len(PERMISSIONS)+1)
perms_columns.insert(0, "pkgName")
for i in range(0, len(PERMISSIONS), 1):
    perms_columns.insert(i+1, PERMISSIONS[i])
perms_columns.insert(len(perms_columns), "Result")


#Directory path names to save benign and malicious system call files
system_calls_home_dir = os.getcwd()+"/system_calls"
benign_system_calls_home_dir = system_calls_home_dir+b_or_m[0]
malicious_system_calls_home_dir = system_calls_home_dir+b_or_m[1]


#Create paths if they don't already exist. If they exist, these commands do nothing.
os.makedirs(system_calls_home_dir, exist_ok = True)
os.makedirs(benign_system_calls_home_dir, exist_ok = True)
os.makedirs(malicious_system_calls_home_dir, exist_ok = True)


#defines path name for permissions csv folder, and creates it.
path_directory = os.getcwd()+'/PermissionsCsv'
os.makedirs(path_directory, exist_ok = True)

vec_perm = len(PERMISSIONS)
dataset = []

#Function creates the permissions csv file for the first time and then opens in append mode.
def create_perms_csv():
    dataset.append(perms_columns)
    pd.DataFrame.to_csv(pd.DataFrame(dataset), path_directory+'/Perms_Malicious.csv', mode = 'a', index = False, header = False)

#Reboots device
def reboot(device):
    os.system('adb -s '+device+' reboot')
    
#Enables wifi on the device        
def enable_wifi(device):
    os.system("adb -s "+device+" shell 'svc wifi enable'")
    print("wifi enabled")

#Stops the app and kills it's processes
def stop_app(pkg_name, device):
    os.system("adb -s "+device+" shell am force-stop "+pkg_name)
    os.system("adb -s "+device+" shell am kill "+pkg_name)
    sleep(2)    
    print("App stopped")
    
 
#Installs an app on the device
def install_app(apk_file, pkg_name, device):
    command_1 = 'adb -s '+device+' install '+apk_file
    subprocess.call(command_1, shell=True)
    print("App "+pkg_name+" installed") 
    

#Uninstalls an app on the device
def uninstall_app(pkg_name, device):
    command_2 = 'adb -s '+device+' uninstall '+pkg_name
#    os.system(command_2)
    subprocess.call(command_2, shell=True)
    
    sleep(2)
    print("App "+pkg_name+" uninstalled")    
    
    
#Generates the permission vector for an apk file and appends it to the permissions dataset    
def gen_perm_vector(apk_file, pkg_name):
    try:
	    a = APK(apk_file)
    except:
        return None

    try:
        permissions = a.get_permissions()
        vector = [] * (vec_perm+1)
        vector.append('1-'+pkg_name)
        for permission in PERMISSIONS:
            hit = 1 if permission in permissions else 0
            vector.append(hit)
        vector.insert(len(vector), 1)   #The 1 here indicates malicious class
        dataset.append(vector)        
        print("*********************************"+pkg_name+"*********************************")        
    except:
        return None


#Function for collecting pcaps and saving it on PC
def collect_pcaps(pkg_name, device):
    
    monkey_command = ["adb","-s", device, "shell", "monkey", "-p", pkg_name, "-c", "android.intent.category.LAUNCHER","1"]
    #os.system(monkey_command)
    subprocess.call(monkey_command, shell=True)
    print("Activity Launched!")    

    #tcp_command = 'tcpdump -W 1 -i wlp3s0 -G 90 -w '+dir_path+'apk_'+str(i)+'.pcap'
    tcp_command = 'tcpdump -W 1 -i wlp0s20f3 -G 90 -w '+malicious_pcaps_dir_path+'/1-'+pkg_name+'.pcap' 
    tcpdump_command_list = tcp_command.split()
    print("tcp dump starting.....")
    res = subprocess.Popen(tcpdump_command_list, stdin = subprocess.PIPE, stdout = subprocess.PIPE,stderr = subprocess.PIPE)
    print("Monkey started!!")
     
    #then = time.time()
    while str(res.poll()) == "None":
        subprocess.call(["adb", "-s", device,"shell", "monkey", "--throttle", "500", "-p", pkg_name, "-v", "150"])
        sleep(2)
    print("tcp dump and monkey stopped!")
    print('pcap File Saved!')
    

#Function for collecting system call traces as txt file and saving it on PC
def collect_system_calls(pkg_name, device):
    # launch the apk
    subprocess.call(["adb","-s", device, "shell", "monkey", "-p", pkg_name, "-c", "android.intent.category.LAUNCHER","1"])
    sleep(5)

    try:    # get the pid of the apk
        out = subprocess.Popen("adb -s "+device+" shell ps -A | grep " + pkg_name, shell=True, stdout=subprocess.PIPE)
        apk_pid = out.stdout.read().split()[1].decode()
    except IndexError as err:
        print(err)
    else:
        # construct trace file name
        trace_file_name = "1-"+pkg_name+".txt"
    
            # strace
      # cmd = "adb shell strace -o /data/local/tmp/" + packageName[index] + "_2000.txt -T -tt -e trace=all -f -p " + zygote_pid
        cmd1 = "adb -s "+device+" shell strace -o /data/local/tmp/" + trace_file_name + " -T -tt -e trace=all -p " + apk_pid
        subprocess.Popen(cmd1, shell=True)
        
           # monkey test 
        print("*** Start Test... ***\n")
        subprocess.call(["adb", "-s", device, "shell", "monkey", "--throttle", "500", "-p", pkg_name, "-v", "150"])
        #return trace_file_name
    
           # get pid of strace and kill strace   
        try:
            out = subprocess.Popen("adb -s "+device+" shell ps -A | grep " + pkg_name,shell=True,stdout=subprocess.PIPE)
            strace_pid = out.stdout.read().split()[1].decode()
            subprocess.call(["adb", "-s", device, "shell", "kill", strace_pid])
        except IndexError as err:
            print(err)


        finally:
           # pull the log file
            cmd2 = "adb -s "+device+" pull /data/local/tmp/" + trace_file_name + " " + malicious_system_calls_home_dir+ "/"
            subprocess.call(cmd2, shell=True)   
           # delete the log file in the emulator
            subprocess.call(["adb", "-s", device, "shell", "rm -f", "/data/local/tmp/" + trace_file_name])
            print('Trace File Saved!')


#Writing the permissions dataframe to a csv file
def write_to_perms_benign_csv():
    dataset_real = pd.DataFrame(dataset)
    pd.DataFrame.to_csv(dataset_real[-1:], 
                        path_directory+'/Perms_Malicious.csv', 
                        index = False, 
                        mode = 'a', 
                        header = False)
    print("Write Successfull")

 
 
#Main function for data collection. 
for i in range(1970,2000,1):

    
    print("****************************Value of i = "+str(i)+"***************************************")

    if i == 1000:
        create_perms_csv()
    
    gen_perm_vector(apk[i], pkg[i])
    write_to_perms_benign_csv() 
    
    
    
    
    
    install_app(apk[i], pkg[i], emulator)
    
    reboot(emulator)
    sleep(60)
    
    enable_wifi(emulator)
    collect_system_calls(pkg[i], emulator)

    stop_app(pkg[i], emulator)
    
    uninstall_app(pkg[i], emulator)

    
    
    
    
    
    install_app(apk[i], pkg[i], phone)
    
    reboot(phone)
    sleep(60)
    
    enable_wifi(phone)
    collect_pcaps(pkg[i], phone)
    
    stop_app(pkg[i], phone)
    
    uninstall_app(pkg[i], phone)
    
