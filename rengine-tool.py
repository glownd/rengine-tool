import requests
from urllib3.exceptions import InsecureRequestWarning
import argparse
from getpass import getpass

#Import custom classes
from Classes.re_authorize import REAuthorize
from Classes.re_target import RETarget
from Classes.re_scan import REScan

#Supress HTTPS warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parent_parser = argparse.ArgumentParser(add_help=False)
main_parser = argparse.ArgumentParser()
option_subparsers = main_parser.add_subparsers(title="options",
                    dest="options")

main_parser.add_argument("-oj", action="store_true",help="JSON output")

#Top Level Commands
auth_parser = option_subparsers.add_parser("authorize", help="",parents=[parent_parser])
target_parser = option_subparsers.add_parser("target", help="",parents=[parent_parser])
organization_parser = option_subparsers.add_parser("organization", help="",parents=[parent_parser])
project_parser = option_subparsers.add_parser("project", help="",parents=[parent_parser])
scan_parser = option_subparsers.add_parser("scan", help="",parents=[parent_parser])
engine_parser = option_subparsers.add_parser("engine", help="",parents=[parent_parser])

#Target Actions
target_action_subparser = target_parser.add_subparsers(title="target_action",dest="target_action_command")
target_add_parser = target_action_subparser.add_parser("add", help="Add target", parents=[parent_parser])
target_remove_parser = target_action_subparser.add_parser("remove", help="Remove target", parents=[parent_parser])
target_list_parser = target_action_subparser.add_parser("list", help="List targets", parents=[parent_parser])
target_listvulns_parser = target_action_subparser.add_parser("list-vulns", help="List target vulnerabilities", parents=[parent_parser])
target_listips_parser = target_action_subparser.add_parser("list-ips", help="List target IPs", parents=[parent_parser])
target_listtech_parser = target_action_subparser.add_parser("list-tech", help="List target technologies", parents=[parent_parser])
target_listports_parser = target_action_subparser.add_parser("list-ports", help="List target ports", parents=[parent_parser])
target_listeps_parser = target_action_subparser.add_parser("list-eps", help="List target endpoints", parents=[parent_parser])

#Organization Actions
organization_action_subparser = organization_parser.add_subparsers(title="organization_action",dest="organization_action_command")
organization_add_parser = organization_action_subparser.add_parser("add", help="Add organization", parents=[parent_parser])
organization_remove_parser = organization_action_subparser.add_parser("remove", help="Remove organization", parents=[parent_parser])
organization_list_parser = organization_action_subparser.add_parser("list", help="List organizations", parents=[parent_parser])
organization_targets_parser = organization_action_subparser.add_parser("list-vulns", help="List organization targets", parents=[parent_parser])

#Project Actions
project_action_subparser = project_parser.add_subparsers(title="project_action",dest="project_action_command")
project_add_parser = project_action_subparser.add_parser("add", help="Add project", parents=[parent_parser])
project_remove_parser = project_action_subparser.add_parser("remove", help="Remove project", parents=[parent_parser])
project_list_parser = project_action_subparser.add_parser("list", help="List projects", parents=[parent_parser])

#Scan Actions
scan_action_subparser = scan_parser.add_subparsers(title="scan_action",dest="scan_action_command")
scan_add_parser = scan_action_subparser.add_parser("add", help="Add scan", parents=[parent_parser])
scan_remove_parser = scan_action_subparser.add_parser("remove", help="Remove scan", parents=[parent_parser])
scan_list_parser = scan_action_subparser.add_parser("list", help="List scans", parents=[parent_parser])
scan_start_parser = scan_action_subparser.add_parser("start", help="Start scan", parents=[parent_parser])
scan_stop_parser = scan_action_subparser.add_parser("stop", help="Stop scan", parents=[parent_parser])

#Engine Actions
engine_action_subparser = engine_parser.add_subparsers(title="engine_action",dest="engine_action_command")
engine_list_parser = engine_action_subparser.add_parser("list", help="List engines", parents=[parent_parser])

#Set up authorization parser
auth_parser.add_argument("-b", metavar="--base-url", action="store",help="URL (ie: https://localhost/)", default="https://localhost/")
auth_parser.add_argument("-u", metavar="--user", action="store",help="ReNgine Username")
auth_parser.add_argument("-p", metavar="--password", action="store",help="ReNgine Password")
auth_parser.add_argument("-d", action="store_true",help="Deletes your session.  You should always do this once finished with the tool")

#Target Parsers Setup
##Setup Target Add Parser
target_add_parser.add_argument("-s", metavar="--slug", action="store",help="ReNgine Project Name / Slug", required=True)
target_add_parser.add_argument("-t", metavar="--target", action="store",help="Target", required=True)
target_add_parser.add_argument("-d", metavar="--desc", action="store",help="Target Description", default="")
target_add_parser.add_argument("-h1", metavar="--team", action="store",help="H1 Team Handle")

##Setup Target List Parser -- Nothing to do here
#TODO
##Setup Target Remove Parser
##Setup Target ListVulns Parser
target_listvulns_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
##Setup Target ListIPs Parser
target_listips_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
##Setup Target ListTech Parser
target_listtech_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
##Setup Target ListPorts Parser
target_listports_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
##Setup Target ListEndPoints Parser
target_listeps_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
target_listeps_parser.add_argument("-pn", metavar="--project-name", action="store",help="Target", required=True)

#Scan
#scan_add_parser
#scan_remove_parser 
scan_list_parser.add_argument("-pn", metavar="--project-name", action="store",help="Target")
#scan_start_parser
#scan_stop_parser
# scan_status/#
# listVulnerability
# QueryInterestingSubdomains
# listInterestingEndpoints
# listIPs
# listScanLogs
# ListTechnology
# ListPorts
# action/stop/scan/
# listEndpoints
# listDirectories

args = main_parser.parse_args()
s: requests.Session
#Authorize
if(args.options == 'authorize'):
    REAuthorize(args)
else:
    s = REAuthorize.getSession()

#Target
if(args.options == 'target'):
    RETarget(args, s)

#Scan
if(args.options == 'scan'):
    REScan(args, s)
