import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning
import json
from tabulate import tabulate

class REProject():
    def __init__(self, args:argparse.Namespace, s:requests.Session):
        
        if(args.project_action_command):
            match args.project_action_command.lower():
                case 'list':
                    self.listProjects(args, s)
                case default:
                    print("What are we doing?")
        else:
            print("No action given, use -h to view actions")

    @staticmethod
    def listProjects(args, s):
        pass