import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning
import json
from tabulate import tabulate

class RETarget():
    def __init__(self, args:argparse.Namespace, s:requests.Session):
        print(args)
        #print(s.cookies['csrftoken'])
        
        if(args.target_action_command):
            match args.target_action_command.lower():
                case 'add':
                    self.addTarget(args, s)
                case 'list':
                    self.listTargets(args, s)
                case default:
                    print("What are we doing?")
        else:
            print("No action given, use -h to view actions")
    
    @staticmethod
    def addTarget(args, s):
        baseUrl = s.cookies['hostname']
        addTargetUrl = baseUrl + 'api/add/target/'
        csrf_token = s.cookies['csrftoken']

        attr = {'description': args.d, 'domain_name': args.t, "slug": args.s,'h1_team_handle': args.h1, }
        headers = {'Referer': addTargetUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.post(addTargetUrl, json=attr, headers=headers, verify=False)

        #Show Success/Failure
        if "Domain successfully added" in r.text:
            print("Successfully added: " + args.t)
        else:
            print("Error adding: " + args.t)

    @staticmethod
    def listTargets(args, s):
        baseUrl = s.cookies['hostname']
        listTargetsUrl = baseUrl + 'api/listTargets/'

        csrf_token = s.cookies['csrftoken']
        headers = {'Referer': listTargetsUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.get(listTargetsUrl, headers=headers, verify=False)
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
                org = i['organization']
                mrs = i['most_recent_scan']
                slug = str(i['project']['id']) + ' | ' + i['project']['slug']
                ssd = i['start_scan_date']

                data.append([id, name, slug, org, ssd, mrs])

            print (tabulate(data, headers=["ID", "Name", "Slug", "Org", "Scan Started", "Recent Scan"]))