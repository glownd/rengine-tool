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
                case default:
                    print("What are we doing?")
        else:
            print("No action given, use -h to view actions")

    @staticmethod
    def listOrganizations(args, s):
        pass
        baseUrl = s.cookies['hostname']
        listEnginesUrl = baseUrl + 'api/listOrganizations/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listEnginesUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.get(listEnginesUrl, headers=headers, verify=False)
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