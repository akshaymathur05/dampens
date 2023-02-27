#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep 10 13:45:52 2022

@author: akshay
"""



import pandas as pd
import os, subprocess
from time import sleep




#The benign or malicious app source
file_path="/media/akshay/CSTARBackup/azoo_data/"

#Path to file constaining the names of apps and their package names
df = pd.read_csv("azoo_Internet_App_Package.csv")

#Separating apk names and pkg names     
apk = list(df['App_Name'])
pkg = list(df['Pkg_Name'])



b_or_m = ["/benign", "/malicious"]

emulator = "192.168.56.101:5555"





system_calls_home_dir = os.getcwd()+"/system_calls"
benign_system_calls_home_dir = system_calls_home_dir+b_or_m[0]
malicious_system_calls_home_dir = system_calls_home_dir+b_or_m[1]


os.makedirs(system_calls_home_dir, exist_ok = True)
os.makedirs(benign_system_calls_home_dir, exist_ok = True)
os.makedirs(malicious_system_calls_home_dir, exist_ok = True)



pkgs_names = []
if(file_path != None):
    apk_file_directory = benign_system_calls_home_dir
    if(not os.path.exists(apk_file_directory)):
        print('%s does not exist' % apk_file_directory)
    else:
        for root, dir, files in os.walk(apk_file_directory):
            pkgs_names.extend(file_name for file_name in files)

pkgName = []
for item in pkgs_names:
    pkgName.append(item[2:-4])

app_pkg = {}
for i in range(2000,3000,1):
    if pkg[i] not in pkgName:
        app_pkg[apk[i]] = pkg[i]


def enable_wifi(device):
    os.system("adb -s "+device+" shell 'svc wifi enable'")
    print("wifi enabled")


def stop_app(pkg_name, device):
    os.system("adb -s "+device+" shell am force-stop "+pkg_name)
    os.system("adb -s "+device+" shell am kill "+pkg_name)
    sleep(2)    
    print("App stopped")
    
 

def install_app(apk_file, pkg_name, device):
    command_1 = 'adb -s '+device+' install '+apk_file
    subprocess.call(command_1, shell=True)
    print("App "+pkg_name+" installed") 
    
    
def uninstall_app(pkg_name, device):
    command_2 = 'adb -s '+device+' uninstall '+pkg_name
#    os.system(command_2)
    subprocess.call(command_2, shell=True)
    
    sleep(2)
    print("App "+pkg_name+" uninstalled")    
    


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
        trace_file_name = "0-"+pkg_name+".txt"
    
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
            cmd2 = "adb -s "+device+" pull /data/local/tmp/" + trace_file_name + " " + benign_system_calls_home_dir+ "/"
            subprocess.call(cmd2, shell=True)   
           # delete the log file in the emulator
            subprocess.call(["adb", "-s", device, "shell", "rm -f", "/data/local/tmp/" + trace_file_name])
            print('Trace File Saved!')



for apk_file, pkg_name in app_pkg.items():

    
    print("****************************Package Name = "+pkg_name+"***************************************")
    
    # gen_perm_vector(apk[i], pkg[i])
    # write_to_perms_benign_csv() 
    
    
    
    enable_wifi(emulator)
    
    install_app(apk_file, pkg_name, emulator)
    
    collect_system_calls(pkg_name, emulator)

    stop_app(pkg_name, emulator)
    
    uninstall_app(pkg_name, emulator)

    
    
    
    # enable_wifi(phone)
    
    # install_app(apk[i], pkg[i], phone)
    
    # collect_pcaps(pkg[i], phone)
    
    # stop_app(pkg[i], phone)
    
    # uninstall_app(pkg[i], phone)
    
