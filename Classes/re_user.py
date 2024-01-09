import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning
import json
from tabulate import tabulate

class REUser():
    def __init__(self, args:argparse.Namespace, s:requests.Session):
        
        if(args.user_action_command):
            match args.user_action_command.lower():
                case 'add':
                    self.addUser(args, s)
                case default:
                    print("What are we doing?")
        else:
            print("No action given, use -h to view actions")

    @staticmethod
    def addUser(args, s):
        #Set URLs
        baseUrl = s.cookies['hostname']
        
        addUserUrl = baseUrl + args.pn + '/admin_interface/update?mode=create'

        #Start scan on target
        csrf_token = s.cookies['csrftoken']
        data = {"username": args.u,"role": args.r, "password":args.p}
        headers = {'Referer': addUserUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.post(addUserUrl, json=data, headers=headers, verify=False)

        if(r.status_code == 200):
            print("SUCCESS!")
        else:
            print('ERROR: ' + r.text)