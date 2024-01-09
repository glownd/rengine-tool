import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning
from getpass import getpass
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

        username = REUser.getUsername(args.u)
        password = REUser.getPassword(args.p)
        
        #Add new rengine user
        csrf_token = s.cookies['csrftoken']
        data = {"username": username,"role": args.r, "password": password}
        headers = {'Referer': addUserUrl,'Content-type': 'application/json', 'X-CSRFToken': csrf_token}
        r = s.post(addUserUrl, json=data, headers=headers, verify=False)

        if(r.status_code == 200):
            print("SUCCESS!")
        else:
            print('ERROR: ' + r.text)
    
    @staticmethod
    def getUsername(username):
        if not username:
                username = input("Enter username: ")
        return username
    
    @staticmethod
    def getPassword(password):
        if not password:
                password = getpass("Enter password: ")
        return password