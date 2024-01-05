import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning
import json
from tabulate import tabulate
import datetime

class REScan():
    def __init__(self, args:argparse.Namespace, s:requests.Session):
        
        if(args.scan_action_command):
            match args.scan_action_command.lower():
                case 'list':
                    self.listScans(args, s)
                # case 'list-vulns':
                #     self.listVulns(args, s)
                # case 'list-ips':
                #     self.listIPs(args, s)
                # case 'list-tech':
                #     self.listTech(args, s)
                # case 'list-ports':
                #     self.listPorts(args, s)
                # case 'list-eps':
                #     self.listEndpoints(args, s)
                case default:
                    print("What are we doing?")
        else:
            print("No action given, use -h to view actions")
    
    # @staticmethod
    # def addTarget(args, s):
    #     baseUrl = s.cookies['hostname']
    #     addTargetUrl = baseUrl + 'api/add/target/'
    #     csrf_token = s.cookies['csrftoken']

    #     attr = {'description': args.d, 'domain_name': args.t, "slug": args.s,'h1_team_handle': args.h1, }
    #     headers = {'Referer': addTargetUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
    #     r = s.post(addTargetUrl, json=attr, headers=headers, verify=False)

    #     #Show Success/Failure
    #     if "Domain successfully added" in r.text:
    #         print("Successfully added: " + args.t)
    #     else:
    #         print("Error adding: " + args.t)

    @staticmethod
    def listScans(args, s):
        baseUrl = s.cookies['hostname']
        listScansUrl = baseUrl + 'api/listScanHistory/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listScansUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.get(listScansUrl, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = []
            for scan in j:
                id = scan['id']
                progress = scan['current_progress']
                start_date = datetime.datetime.strptime(scan['start_scan_date'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
                stop_date = datetime.datetime.strptime(scan['stop_scan_date'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
                domain = scan['domain']['name']
                scan_type = scan['scan_type']['engine_name']

                data.append([id, domain, start_date, stop_date, progress, scan_type])

            print (tabulate(data, headers=["ID", "Domain", "Start", "Stop", "Progress", "Type"]))
    