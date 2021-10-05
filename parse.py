#!/usr/bin/python3
import sys
import re
import subprocess
import os
import ipinfo
import webb
import shodan
import json

def extract_ipv4():
    file = input("Filename: ")
    f = open(file,'r')
    text = f.read()
    ips = []
    regex = re.findall(r'^((25[0-5]|2[0-4][0-9]|[1]?[1-9][0-9]?).){3}(25[0-5]|2[0-4][0-9]|[1]?[1-9]?[0-9])$',text)
    if regex is not None:
        for match in regex:
            if match not in ips:
                ips.append(match)
    print(ips)
    f.close()
    return(ips)

def extract_ipv6():
    file = input("Filename: ")
    f = open(file,'r')
    text = f.read()
    ips = []
    regex = re.findall(r'^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)',text)
    if regex is not None:
        for match in regex:
            if match not in ips:
                ips.append(match)
    f.close()
    return(ips)

def save(ip, traceroute_results, ping_results, nmap_results, geolocated_one_results, geolocated_two_results, info):
    with open(ip + '.txt', 'w') as f:
        f.write("**********************************************************************************\n")
        f.write("***************************" + 'ip ' + ip + " ***********************************\n")
        f.write("##################################################################################\n")
        f.write("Traceroute\n")
        f.write(traceroute_results)
        f.write("##################################################################################\n")
        f.write(str(ping_results) + '\n')
        f.write("##################################################################################\n")
        f.write(nmap_results)
        f.write("##################################################################################\n")
        f.write(json.dumps(geolocated_one_results) + '\n')
        f.write("##################################################################################\n")
        f.write(json.dumps(geolocated_two_results) + '\n')
        f.write("##################################################################################\n")
        f.write('\n')
        print("Output file: " + ip + '.txt')
        if info is not False:
            f.write(info + '\n')
        else:
            pass

def ping(ip):
    param = "-c"
    command = ['ping', param, '5', ip]
    try:
        output = subprocess.check_output(command)
        return output
    except:
        return("Ping returned non 0 exit status.")

def nmap(ip, ipv4):
    param_one = '-sS'
    param_two = '-sU'
    param_three = '-Pn'
    param_four = '-6'
    if ipv4 == True:
        command = ['nmap', "--host-timeout", "50", param_one, param_two, param_three, ip]
        process = subprocess.run(command, check=True, stdout=subprocess.PIPE, universal_newlines=True)
        output = process.stdout
        return output
    else:
        command = ['nmap', "--host-timeout", "50", param_four, param_one, param_two, param_three, ip]
        process = subprocess.run(command, check=True, stdout=subprocess.PIPE, universal_newlines=True)
        output = process.stdout
        return output

def geolocate_one(ip):
    access_token = '5d081136484ec7'
    handler = ipinfo.getHandler(access_token)
    details = handler.getDetails(ip)
    return(details.all)

def geolocate_two(ip):
    search_string = 'https://api.ipgeolocation.io/ipgeo?apiKey=81f03c6b20524c57932ea021f5bfb701&ip='
    command = ['curl', search_string + ip]
    process = subprocess.run(command, check=True, stdout=subprocess.PIPE, universal_newlines=True)
    output = process.stdout
    return output

def traceroute(ip, ipv4):
    param_one = "-w"
    param_two = "-m"
    if ipv4 == True:
        command = ['traceroute', param_one, '1', param_two, '20', ip]
        process = subprocess.run(command, check=True, stdout=subprocess.PIPE, universal_newlines=True)
        output = process.stdout
        return output
    else:
        command = ['traceroute6', param_one, '1', param_two, '20', ip]
        process = subprocess.run(command, check=True, stdout=subprocess.PIPE, universal_newlines=True)
        output = process.stdout
        return output

def scan_v4(ip):
    traceroute_results = traceroute(ip, True)
    ping_results = ping(ip)
    nmap_results = nmap(ip, True)
    geolocated_one_results = geolocate_one(ip)
    geolocated_two_results = geolocate_two(ip)
    try:
        info = api.host(ip)
        save(ip, traceroute_results, ping_results, nmap_results, geolocated_one_results, geolocated_two_results, info)
    except:
        pass
        info = False
        save(ip, traceroute_results, ping_results, nmap_results, geolocated_one_results, geolocated_two_results, info)

def scan_v6(ip):
    traceroute_results = traceroute(ip, False)
    ping_results = ping(ip)
    nmap_results = nmap(ip, False)
    geolocated_one_results = geolocate_one(ip)
    geolocated_two_results = geolocate_two(ip)
    try:
        info = api.host(ip)
        save(ip, traceroute_results, ping_results, nmap_results, geolocated_one_results, geolocated_two_results, info)
    except:
        pass
        info = False
        save(ip, traceroute_results, ping_results, nmap_results, geolocated_one_results, geolocated_two_results, info)

def Mass_scan():
    ipv4 = extract_ipv4()
    ipv6 = extract_ipv6()
    api = shodan.Shodan('CAeUU79CVgsbphqCM1mVQI69kWGm79Fk')

    for i in ipv4:
        traceroute_results = traceroute(i, True)
        ping_results = ping(i)
        nmap_results = nmap(i, True)
        geolocated_one_results = geolocate_one(ip)
        geolocated_two_results = geolocate_two(ip)
        try:
            info = api.host(ip)
            save(ip, traceroute_results, ping_results, nmap_results, geolocated_one_results, geolocated_two_results, info)
        except:
            pass
            info = False
            save(ip, traceroute_results, ping_results, nmap_results, geolocated_one_results, geolocated_two_results, info)

    for i in ipv6:
        traceroute_results = traceroute(i, False)
        ping_results = ping(i)
        nmap_results = nmap(i, False)
        geolocated_one_results = geolocate_one(ip)
        geolocated_two_results = geolocate_two(ip)
        try:
            info = api.host(ip)
            save(ip, traceroute_results, ping_results, nmap_results, geolocated_one_results, geolocated_two_results, info)
        except:
            pass
            info = False
            save(ip, traceroute_results, ping_results, nmap_results, geolocated_one_results, geolocated_two_results, info)
#extract_ipv4()

def main():
    scan_type = input('1: Single Address Scan\n2: Mass Address Scan\n')
    if scan_type == "1":
        type = input("1: IPv4\n2: IPv6:\n")
        if type == '1':
            ip = input("Enter Address: ")
            scan_v4(ip)
            return 0
        if type == '2':
            ip = input("Enter Address: ")
            scan_v6(ip)
            return 0
        else:
            print("Not an option.")
            return 1
    if scan_type == "2":
        Mass_scan()
    else:
        print("Not an option.")
main()
