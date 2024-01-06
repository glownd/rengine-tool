import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning
import json
from tabulate import tabulate

class REEngine():
    def __init__(self, args:argparse.Namespace, s:requests.Session):
        
        if(args.engine_action_command):
            match args.engine_action_command.lower():
                case 'list':
                    self.listEngines(args, s)
                case default:
                    print("What are we doing?")
        else:
            print("No action given, use -h to view actions")

    @staticmethod
    def listEngines(args, s):
        baseUrl = s.cookies['hostname']
        listEnginesUrl = baseUrl + 'api/listEngines/'

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
            for i in j['engines']:
                id = i['id']
                name = i['engine_name']
                tasks = i['tasks']

                data.append([id, name, tasks])

            print (tabulate(data, headers=["ID", "Name", "Tasks"]))
    