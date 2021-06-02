#!/usr/bin/python3

import sys
import argparse
import requests
import random
import time
from pathlib import Path
import readchar
import csv
import json
import ipaddress

class CustomFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass

class Proxy:
    def __init__(self, *args, **kwargs):
        if len(args) == 1:
            self.initializeFromString(args[0])
        elif len(args) == 2:
            self.initializeFromIpPort(args[0], args[1])

    def initializeFromString(self, ip_port):
        splitted_ip_port = ip_port.split(':')
        self.ip = splitted_ip_port[0]
        self.port = int(splitted_ip_port[1])

    def initializeFromIpPort(self, ip, port):
        self.ip = ip
        self.port = port

    def __str__(self):
        return f"{self.ip}%3A{str(self.port)}"

def print_banner():
    print(
"""===============================================================

  __|        _|    _ \                __|_)          |
\__ \  _` |  _|-_) __/_|_ \\ \ / |  | _|  |   \   _` |  -_)  _|
____/\__,_|_|\___|_|_|\___/ _\_\\_, |_|  _|_| _|\__,_|\___|_|
                                    ___/

SafeProxyFinder | A script to find and check free proxies
Written by Jeremy MEYER


Usage | python3 safeproxyfinder.py

===============================================================



""")

def print_if_verbose(*objects, sep=' ', end='\n', file=sys.stdout, flush=False):
    global verbose
    if verbose:
        print(*objects, sep=sep, end=end, file=file, flush=flush)

def ip_port_to_proxy(ip, port):
    # ip part
    try:
        ipaddress.ip_address(ip)
        try:
            port_nb = int(port)
            if 1 <= port_nb <= 65535:
                return Proxy(ip, port_nb)
            return None
        except:
            return None
    except:
        return None

def parse_conf(configfilepath):
    global verbose
    global error

    proxies = []
    with open(configfilepath, "r") as configfile:
        # First try to read it as a CSV file
        try:
            classic_csv = csv.reader(configfile, strict=True)
            print_if_verbose(f"[*] {configfilepath} detected as a CSV file.")
            for csv_row in classic_csv:
                csv_proxy = ip_port_to_proxy(csv_row[0], csv_row[1])
                if csv_proxy is None:
                    print(f"[!] The CSV file {configfilepath} has an invalid proxy: {csv_row}")
                    if not error:
                        sys.exit(3)
                else:
                    proxies.append(csv_proxy)
        except csv.Error:
            # Then a "colon"SV
            try:
                classic_txt = csv.reader(configfile, delimiter=':', strict=True)
                print_if_verbose(f"[*] {configfilepath} detected as a TXT file.")
                for txt_row in classic_txt:
                    txt_proxy = ip_port_to_proxy(txt_proxy[0], txt_proxy[1])
                    if txt_proxy is None:
                        print(f"[!] The TXT file {configfilepath} has an invalid proxy: {txt_row}")
                        if not error:
                            sys.exit(3)
                    else:
                        proxies.append(txt_proxy)
            except csv.Error:
                # Then as JSON
                try:
                    classic_json = json.load(configfile)
                    print_if_verbose(f"[*] {configfilepath} detected as a JSON file.")
                    # Check static first
                    if classic_json["static"]:
                        for json_proxy in classic_json["static"]:
                            static_proxy = ip_port_to_proxy(json_proxy["ip"], json_proxy["port"])
                            if static_proxy is None:
                                print(f"[!] The JSON file {configfilepath} has an invalid static proxy : {json_proxy}")
                                if not error:
                                    sys.exit(3)
                            else:
                                proxies.append(static_proxy)

                    # Check dynamic then
                    if classic_json["dynamic"]:
                        for json_proxy in classic_json["dynamic"]:
                            print_if_verbose("")
                except json.JSONDecodeError as jde:
                    print(f"[!] The file {configfilepath} is not in a valid format (JSON, CSV, TXT).")
                    print(jde.msg)
                    sys.exit(3)
    print_if_verbose(f"[+] {len(proxies)} proxies added to test from {configfilepath}")
    return proxies

def check_proxies(proxies):
    global verbose
    global ignore
    global limit

    try:
        start_time = round(time.time() * 1000)
        all_res = None
        joined_proxies = "%0A".join(list(map(str, proxies)))
        print_if_verbose(f'[*] Asking https://proxycheck.haschek.at/api.php?proxies={joined_proxies}&key=...')
        response = requests.get(f'https://proxycheck.haschek.at/api.php?proxies={joined_proxies}&key=')
        if response.status_code != 200:
            raise ApiError('GET /api.php {}'.format(response.status_code))
        res = response.json()
        if res["status"] == "pending":
            # Add finished proxies
            all_res = {k: v for k, v in res["results"].items() if "score" in v}
            print_if_verbose(all_res)
            print_if_verbose(f'[+] {len(all_res)} / {len(proxies)} checked...')

            # For each pending proxies, check them while there is at least one pending proxy
            pending_proxies = {k: v for k, v in res["results"].items() if "score" not in v}
            while pending_proxies and (limit is None or (round(time.time() * 1000) - start_time) < limit):
                rand_ip, rand_stats = random.choice(list(pending_proxies.items()))
                rand_hash = rand_stats["hash"]

                response = requests.get(f'https://proxycheck.haschek.at/api.php?hash={rand_hash}&key=')
                if response.status_code != 200:
                    raise ApiError('GET /api.php {}'.format(response.status_code))

                res = response.json()
                # If finally reached, filter it without the computed hash
                if res["status"] != "pending":
                    all_res.update(res["results"])
                    pending_proxies = {k: v for k, v in pending_proxies.items() if v["hash"] != rand_hash}
                    print_if_verbose(res["results"])
                    print_if_verbose(f'[+] {len(all_res)} / {len(proxies)} checked...')

        else:
            all_res = res["results"]
    except KeyboardInterrupt:
        print_if_verbose("[!] Aborted !!!")
    except:
        raise
    finally:
        if ignore:
            return {k: v for k,v in all_res.items() if v["status"] != "down"}
        else:
            return all_res

def main():
    parser = argparse.ArgumentParser(description='Find proxies and give their score to know if there are safe.', prog=sys.argv[0], add_help=False, formatter_class=CustomFormatter, conflict_handler='resolve', epilog=
"""Feel free to fork, or even contribute to it by creating an issue or
sending a pull request https://github.com/Eneru/safeproxyfinder .

/!\\                                                        /!\\
        THIS CHECK ISN'T 100% SAFE, AND USES PROXYCHECK.
        BE SURE TO UNDERSTAND THE RISK BEFORE USING FREE
        PROXIES
/!\\                                                        /!\\""")
    filesgroup = parser.add_argument_group('INPUT/OUTPUT')
    filesgroup.add_argument('configfiles', nargs='+', action='extend', help="config file that lists proxies' sources")
    filesgroup.add_argument('-o', '--output', action='store', default='out.txt', help='output file path and name', dest='out')
    filesgroup.add_argument('-s', '--scrape', action='store_true', help='allows scraping websites')

    parsing_rules = parser.add_argument_group('PARSING RULES')
    parsing_rules.add_argument('-e', '--error', action='store_true', help='ignore when there is a line in error in conf files')
    parsing_rules.add_argument('-i', '--ignore', action='store_true', help='ignore the proxies that are down in the results')
    parsing_rules.add_argument('-l', '--limit', action='store', default=None, help='limit time to wait the results (in ms)', type=int)

    misc = parser.add_argument_group('MISC.')
    misc.add_argument('-b', '--banner', action='store_false', help="doesn't print the banner")
    misc.add_argument('-f', '--format', action='store_true', help='show help about the format and exit')
    misc.add_argument('-h', '--help', action='help', help='show this help message and exit')
    misc.add_argument('-v', '--verbose', action='store_true', help='activate the verbosity to print more informations')
    misc.add_argument('-V', '--Version', action='version', version='%(prog)s 1.0.0')
    args = parser.parse_args()

    if args.format:
        print(
"""JSON, TXT, CSV files are allowed, and they must have a specific format:
- JSON must have the following schema
{
    "static":
    [
        {
            "ip": "127.0.0.1",
            "port": "9080"
        },
        ...
    ],
    "dynamic":
    [
        {
            "host": "https://spys.me/proxy.txt",
            "head": 9, // [optional] precise how much line to skip from head
            "tail": 2, // [optional] precise how much line to skip at the end
            "format": "$ip$:$port$ (.*)"    // perl regex format with
                                            // $ip$ for ip
                                            // $port$ for the port
            "scrape": false // if true, then format will not be used
                            // be sure to have the rights to scrape
        }
    ]
}
-   TXT (resp. CSV) will only work for static formats and must only contain
    ip:port (resp. ip,port) per line.
""")
        sys.exit()

    if args.banner:
        print_banner()

    global verbose
    global ignore
    global limit
    global error

    verbose = args.verbose
    ignore = args.ignore
    error = args.error

    configfilespaths = args.configfiles
    badpaths = [badpath for badpath in configfilespaths if not Path(badpath).is_file()]
    if len(badpaths) > 0:
        print("[!] The following files doesn't exist: ", ', '.join(badpaths))
        sys.exit(1)
    print_if_verbose("[*] Configuration's files used: ", ', '.join(configfiles))
    print_if_verbose("[*] Parsing configuration's files ...")
    proxies = []
    for configfilepath in configfilespaths:
        proxies.append(parse_conf(configfilepath))

    outputfilepath = args.out
    if Path(outputfilepath).is_file():
        rep = ''
        while rep.lower not in ['y', 'n']:
            print("[!] The file already exists ! Are you sure to want to overwrite it ? (y/N) ", end='')
            rep = repr(reachar.readchar())
        if rep == 'n':
            print_if_verbose("[!] Aborted !!!")
            sys.exit()
    else:
        print_if_verbose("[*] Output file to write the result: ", outputfiles)

        scrape = args.scrape
        if scrape:
            print_if_verbose("[*] Websites scraping is allowed.")

        limit = args.limit
        if limit is None:
            print_if_verbose("[*] No time limit configured, you can cancel (and get actual result) by pressing Ctrl-C.")
        elif limit.isdigit():
            print_if_verbose("[*] Time limit configured to ", limit, " ms.")
        else:
            print("[!] The time limit must be a number !!!")
            sys.exit(2)

        print_if_verbose("\n\n\n")

        with open(outputfilepath, "w", encoding = 'utf-8') as outputfile:
            all_res = check_proxies(proxies)
            outputfile.write(all_res)
            outputfile.close()

if __name__ == "__main__":
    main()
