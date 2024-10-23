#!/bin/python

#import pstats
#import cProfile
#import timeit
import os
import fnmatch
import json
import re
import subprocess

def check_imunify360_modsec_rules_installed():
    path = "/etc/apache2/conf.d/modsec_vendor_configs"
    entries = os.listdir(path)

    match_imunify360_modsec_rules_installed = [entry for entry in entries if fnmatch.fnmatch(entry,"imunify360*") and os.path.isdir(os.path.join(path,entry))]

    return match_imunify360_modsec_rules_installed if match_imunify360_modsec_rules_installed else None

def write_json_file(json_data,json_file):
    with open(json_file, 'w') as f:
        json.dump(json_data, f)

def getrule_json():

    list_rule = check_imunify360_modsec_rules_installed()
    for vendor_id in list_rule:
        command = [
            "/usr/local/cpanel/bin/whmapi1",
            "modsec_get_rules",
            f"vendor_id={vendor_id}",
            "--output=json",
        ]

        # try for exception handling
        try:
            # execute the command by using subprocess
            json_rules = subprocess.run(
                command,
                check=True,
                shell=False,
                stdout=subprocess.PIPE,
            )

            json_rules = json.loads(json_rules.stdout.decode("utf-8"))

            rules_ids = [   
                j["id"]
                for j in json_rules["data"]["chunks"]
                if "WordPress" in j["meta_msg"]
                and re.search(
                    r"CVE|exploit|Vulnerability|[]=<]|LFI|RCE|RFI|(File Upload)",
                    j["meta_msg"],
                )
            ]
            json_rules_id = { "rule": rules_ids }

            write_json_file(json_rules_id, "rule_vuln_wp.json")
            print(rules_ids)


        except subprocess.CalledProcessError as e:
            print(f"Error executing command. Exit code: {e.returncode}")
            print(e.stdout)
            print(e.stderr)



def main():
    getrule_json()

if __name__ == "__main__":
    main()
