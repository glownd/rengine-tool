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
                case 'status':
                    self.listScanStatus(args, s)
                # case 'list-vulns':
                #     self.listVulns(args, s)
                case 'list-ips':
                    self.listIPs(args, s)
                case 'list-tech':
                    self.listTech(args, s)
                # case 'list-ports':
                #     self.listPorts(args, s)
                case 'list-eps':
                    self.listEndpoints(args, s)
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
                start_date = '' if scan['start_scan_date'] is None else datetime.datetime.strptime(scan['start_scan_date'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
                stop_date = '' if scan['stop_scan_date'] is None else datetime.datetime.strptime(scan['stop_scan_date'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
                domain = scan['domain']['name']
                scan_type = scan['scan_type']['engine_name']

                data.append([id, domain, start_date, stop_date, progress, scan_type])

            print (tabulate(data, headers=["ID", "Domain", "Start", "Stop", "Progress", "Type"]))
    
    @staticmethod
    def listScanStatus(args, s):
        baseUrl = s.cookies['hostname']
        listScanStatusUrl = baseUrl + 'api/scan_status/'

        csrf_token = s.cookies['csrftoken']
        params = {'project': args.pn}
        headers = {'Referer': listScanStatusUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.get(listScanStatusUrl, params=params, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = REScan.formatScanStatus(j)
            print (tabulate(data, headers=["Status", "ID", "Domain", "Start", "Stop", "Progress", "Type"]))
    
    def formatScanStatus(j):
        data = []
        types = ['pending','scanning','completed']
        for t in types:
            for scan in j['scans'][t]:
                status = t.upper()
                id = scan['id']
                progress = scan['current_progress']
                start_date = '' if scan['start_scan_date'] is None else datetime.datetime.strptime(scan['start_scan_date'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
                stop_date = '' if scan['stop_scan_date'] is None else datetime.datetime.strptime(scan['stop_scan_date'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
                domain = scan['domain']['name']
                scan_type = scan['scan_type']['engine_name']
                data.append([status, id, domain, start_date, stop_date, progress, scan_type])
        return data
    
    @staticmethod
    def listIPs(args, s):
        baseUrl = s.cookies['hostname']
        listIPsUrl = baseUrl + 'api/queryIps/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listIPsUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        params = {'scan_id': args.si}
        r = s.get(listIPsUrl, params=params, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = []
            for i in j['ips']:
                id = i['id']
                address = i['address']
                is_cdn = i['is_cdn']
                version = i['version']
                is_private = i['is_private']
                reverse_pointer = i['reverse_pointer']
                geo_iso = i['geo_iso']

                #TODO: Need to get a scan with ports & ip_subscan_ids to see the output
                #TODO: Loop through ports / ip_subscan_idsS
                data.append([id, address, is_cdn, version, is_private, reverse_pointer, geo_iso])

            print (tabulate(data, headers=["ID", "Address", "IsCDN", "Version", "IsPrivate", "Reverse Pointer", "GeoISO"]))

    @staticmethod
    def listEndpoints(args, s):
        baseUrl = s.cookies['hostname']
        listEndpointsUrl = baseUrl + 'api/queryEndpoints/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listEndpointsUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        attr = {'scan_id': args.si}
        r = s.get(listEndpointsUrl, params=attr, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = []
            for i in j['endpoints']:
                url = i['http_url']
                title = i['page_title']
                status = i['http_status']
                webserver = i['webserver']

                data.append([url, title, status, webserver])

            print (tabulate(data, headers=["URL", "Title", "Status", "Webserver"]))

    @staticmethod
    def listTech(args, s):
        baseUrl = s.cookies['hostname']
        listTechUrl = baseUrl + 'api/queryTechnologies/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listTechUrl,'Content-type': 'application/x-www-form-urlencoded', 'X-CSRFToken': csrf_token}
        attr = {'scan_id': args.si}
        r = s.get(listTechUrl, params=attr, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = []
            for i in j['technologies']:
                name = i['name']

                data.append([name])

            print (tabulate(data, headers=["Name"]))