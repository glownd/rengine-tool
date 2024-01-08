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
                case 'list-vulns':
                    self.listVulns(args, s)
                case 'list-ips':
                    self.listIPs(args, s)
                case 'list-tech':
                    self.listTech(args, s)
                case 'list-ports':
                    self.listPorts(args, s)
                case 'list-eps':
                    self.listEndpoints(args, s)
                case 'list-scanlogs':
                    self.listScanLogs(args, s)
                case 'start':
                    self.startScan(args, s)
                case 'stop':
                    self.stopScan(args, s)
                case 'delete':
                    self.deleteScan(args,s)
                case default:
                    print("What are we doing?")
        else:
            print("No action given, use -h to view actions")

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
    
    @staticmethod
    def listPorts(args, s):
        baseUrl = s.cookies['hostname']
        listPortsUrl = baseUrl + 'api/queryPorts/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listPortsUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        attr = {'scan_id': args.si}
        r = s.get(listPortsUrl, params=attr, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = []
            for i in j['ports']:
                number = i['number']
                service = i['service_name']
                description = i['description']
                uncommon = i['is_uncommon']

                data.append([number, service, description, uncommon])

            print (tabulate(data, headers=["Port", "Service", "Desc", "Uncommon"]))
    
    @staticmethod
    def listVulns(args, s):
        baseUrl = s.cookies['hostname']
        listVulnsUrl = baseUrl + 'api/listVulnerability/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listVulnsUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        attr = {'scan_history': args.si}
        r = s.get(listVulnsUrl, params=attr, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = []
            for i in j['results']:
                id = i['id']
                name = i['name']
                severity = i['severity']
                description = i['description']
                cvss_score = i['cvss_score']
                open_status = i['open_status']
                subdomain_name = i['subdomain']['name']

                #Loop through CVEs
                cves = ""
                for cve in i['cve_ids']:
                    cves = cves + cve['name'] + ', '
                data.append([id, name, severity, cvss_score, open_status, description, subdomain_name, cves])

            print (tabulate(data, headers=["ID", "Name", "Severity", "CVSS", "Open", "Description", "Subdomain", "CVEs"]))
    
    @staticmethod
    def listScanLogs(args, s):
        baseUrl = s.cookies['hostname']
        listScanLogsUrl = baseUrl + 'api/listScanLogs/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listScanLogsUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        attr = {'scan_id': args.si}
        r = s.get(listScanLogsUrl, params=attr, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = []
            for i in j['results']:
                time = '' if i['time'] is None else datetime.datetime.strptime(i['time'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
                command = i['command']
                return_code = i['return_code']
                output = '' if i['output'] is None else i['output']
                if(args.wo):
                    print('Time:\t' + time + '\nCommand:\t' + command + '\nReturn Code:\t' + str(return_code) + '\nOutput:\t' + output + '\n')
                else:
                    print('Time:\t' + time + '\nCommand:\t' + command + '\nReturn Code:\t' + str(return_code) + '\n')
    
    #TODO: This should eventually be modified to accept more options
    @staticmethod
    def startScan(args, s):
        #Set URLs
        baseUrl = s.cookies['hostname']
        startScanUrl = baseUrl + 'scan/' + args.pn + '/start/' + args.ti

        #Start scan on target
        csrf_token = s.cookies['csrftoken']
        data = '?csrfmiddlewaretoken=' + csrf_token + '&scan_mode=' + args.ei + '&importSubdomainTextArea=&outOfScopeSubdomainTextarea=&filterPath='
        headers = {'Referer': startScanUrl,'Content-type': 'application/x-www-form-urlencoded', 'X-CSRFToken': csrf_token}
        r = s.post(startScanUrl, data=data, headers=headers, verify=False)

        if("Scan history" in r.text):
            print("SUCCESS")
        else:
            print("FAILURE: Something went wrong!")
    
    @staticmethod
    def stopScan(args, s):
        baseUrl = s.cookies['hostname']
        stopScanUrl = baseUrl + 'api/action/stop/scan/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': stopScanUrl,'Content-type': 'application/json', 'X-Csrftoken': csrf_token}
        if(args.si):
            data = {"scan_id": args.si}
        elif(args.ssi):
            data = {"subscan_id": args.ssi}
        else:
            "ERROR: No scan/sub-scan ID provided."
        
        r = s.post(stopScanUrl, json=data, headers=headers, verify=False)
        j = r.json()
        
        if(j["status"] == True):
            print("SUCCESS!")
        else:
            print("ERROR: " + j["message"])
    
    @staticmethod
    def deleteScan(args, s):
        if(args.ssi):
            REScan.deleteSubScan(args, s)
        else:
            #Set URLs
            baseUrl = s.cookies['hostname']
            
            deleteScanUrl = baseUrl + 'scan/delete/scan/' + args.si

            #Start scan on target
            csrf_token = s.cookies['csrftoken']
            data = {"csrfmiddlewaretoken": csrf_token}
            headers = {'Referer': deleteScanUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
            r = s.post(deleteScanUrl, json=data, headers=headers, verify=False)

            if(r.status_code == 200):
                print("SUCCESS!")
            else:
                print('ERROR: ' + r.text)
    
    @staticmethod
    def deleteSubScan(args, s):
        #Set URLs
        baseUrl = s.cookies['hostname']
        deleteSubScanUrl = baseUrl + 'api/action/rows/delete/'

        #Start scan on target
        csrf_token = s.cookies['csrftoken']
        data = {"type":"subscan","rows":[args.ssi]}
        headers = {'Referer': deleteSubScanUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.post(deleteSubScanUrl, json=data, headers=headers, verify=False)
        j = r.json()
        
        if(j["status"] == True):
            print("SUCCESS!")
        else:
            print("ERROR: " + r.text)