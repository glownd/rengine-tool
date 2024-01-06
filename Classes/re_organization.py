import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning
import json
from tabulate import tabulate

class REOrganization():
    def __init__(self, args:argparse.Namespace, s:requests.Session):
        
        if(args.organization_action_command):
            match args.organization_action_command.lower():
                case 'list':
                    self.listOrganizations(args, s)
                case 'list-targets':
                    self.listOrganizationTargets(args, s)
                case 'add':
                    self.addOrganization(args, s)
                case 'remove':
                    self.removeOrganization(args, s)
                case default:
                    print("What are we doing?")
        else:
            print("No action given, use -h to view actions")

    @staticmethod
    def listOrganizations(args, s):
        baseUrl = s.cookies['hostname']
        listOrganizationsUrl = baseUrl + 'api/listOrganizations/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listOrganizationsUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.get(listOrganizationsUrl, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = []
            for i in j['organizations']:
                id = i['id']
                name = i['name']
                description = i['description']
                pid = i['project']
                dids = i['domains']

                data.append([id, name, description, pid, dids])

            print (tabulate(data, headers=["ID", "Name", "Description", "Project ID", "Domain IDs"]))

    @staticmethod
    def listOrganizationTargets(args, s):
        baseUrl = s.cookies['hostname']
        listOrganizationsUrl = baseUrl + 'api/queryTargetsInOrganization/'

        csrf_token = s.cookies['csrftoken']
        params = {"organization_id": args.oi}
        headers = {'Referer': listOrganizationsUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.get(listOrganizationsUrl, params=params, headers=headers, verify=False)
        j = r.json()

        #If JSON output
        if(args.oj):
            print(json.dumps(j, indent=2))
        #Lets do some formating for non-json output
        else:
            data = []
            for i in j['organization']:
                id = i['id']
                name = i['name']
                description = i['description']
                pid = i['project']
                dids = i['domains']
            
            domains = []
            for d in j['domains']:
                domains.append(d['name'])

            data.append([id, name, description, pid, dids, domains])

            print (tabulate(data, headers=["ID", "Name", "Description", "Project ID", "Domain IDs", "Domains"]))
    
    @staticmethod
    def addOrganization(args, s):
        baseUrl = s.cookies['hostname']
        addOrganizationUrl = baseUrl + '/target/' + args.pn + '/add/organization'

        csrf_token = s.cookies['csrftoken']
        data = {"name": args.on, "description": args.d}
        domains = []
        if ',' in args.ti:
            for args.ti in args.ti.split(','):
                domains.append(int(args.ti))
            data["domains"] = domains
        else:
            data["domains"] = args.ti

        headers = {'Referer': addOrganizationUrl,'Content-type': 'application/x-www-form-urlencoded', 'X-CSRFToken': csrf_token}
        r = s.post(addOrganizationUrl, data=data, headers=headers, verify=False)
        
        if(r.status_code == 200):
            print("Looks successful!")
        else:
            print("ERROR: " + r.status_code)
    
    @staticmethod
    def removeOrganization(args, s):
        baseUrl = s.cookies['hostname']
        removeOrganizationUrl = baseUrl + '/target/delete/organization/' + str(args.oi)

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': removeOrganizationUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.post(removeOrganizationUrl, headers=headers, verify=False)
        
        if(r.status_code == 200):
            print("Looks successful!")
        else:
            print("ERROR: " + r.status_code)