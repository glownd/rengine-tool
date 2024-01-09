import requests
from urllib3.exceptions import InsecureRequestWarning
import argparse
from getpass import getpass

#Import custom classes
from Classes.re_authorize import REAuthorize
from Classes.re_target import RETarget
from Classes.re_scan import REScan
from Classes.re_engine import REEngine
from Classes.re_organization import REOrganization
from Classes.re_project import REProject
from Classes.re_user import REUser

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
user_parser = option_subparsers.add_parser("user", help="",parents=[parent_parser])

#User Actions
user_action_subparser = user_parser.add_subparsers(title="user_action",dest="user_action_command")
user_add_parser = user_action_subparser.add_parser("add", help="Add User", parents=[parent_parser])

#Target Actions
target_action_subparser = target_parser.add_subparsers(title="target_action",dest="target_action_command")
target_add_parser = target_action_subparser.add_parser("add", help="Add target", parents=[parent_parser])
target_delete_parser = target_action_subparser.add_parser("delete", help="Remove target", parents=[parent_parser])
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
organization_targets_parser = organization_action_subparser.add_parser("list-targets", help="List organization targets", parents=[parent_parser])

#Project Actions
# project_action_subparser = project_parser.add_subparsers(title="project_action",dest="project_action_command")
# project_add_parser = project_action_subparser.add_parser("add", help="Add project", parents=[parent_parser])
# project_remove_parser = project_action_subparser.add_parser("remove", help="Remove project", parents=[parent_parser])
# project_list_parser = project_action_subparser.add_parser("list", help="List projects", parents=[parent_parser])

#Scan Actions
scan_action_subparser = scan_parser.add_subparsers(title="scan_action",dest="scan_action_command")
scan_list_parser = scan_action_subparser.add_parser("list", help="List scans", parents=[parent_parser])
scan_start_parser = scan_action_subparser.add_parser("start", help="Start scan", parents=[parent_parser])
scan_stop_parser = scan_action_subparser.add_parser("stop", help="Stop scan", parents=[parent_parser])
scan_delete_parser = scan_action_subparser.add_parser("delete", help="Delete scan", parents=[parent_parser])
scan_status_parser = scan_action_subparser.add_parser("status", help="Get the status of scans", parents=[parent_parser])
scan_listips_parser = scan_action_subparser.add_parser("list-ips", help="Get IP Addresses from scan", parents=[parent_parser])
scan_listeps_parser = scan_action_subparser.add_parser("list-eps", help="Get Endpoints from scan", parents=[parent_parser])
scan_listtech_parser = scan_action_subparser.add_parser("list-tech", help="List found technoligies in scan", parents=[parent_parser])
scan_listports_parser = scan_action_subparser.add_parser("list-ports", help="List found ports in scan", parents=[parent_parser])
scan_listvulns_parser = scan_action_subparser.add_parser("list-vulns", help="List scan vulnerabilities", parents=[parent_parser])
scan_listscanlogs_parser = scan_action_subparser.add_parser("list-scanlogs", help="List a scans logs", parents=[parent_parser])

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

#Target
##list -- Nothing to do here
##remove
target_delete_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
##listvulns
target_listvulns_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
##listIPs
target_listips_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
##listTech
target_listtech_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
##listPorts
target_listports_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
##listEndPoints
target_listeps_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target", required=True)
target_listeps_parser.add_argument("-pn", metavar="--slug", action="store",help="Project name / slug", required=True)

#Scan
##delete
scan_delete_group = scan_delete_parser.add_mutually_exclusive_group(required=True)
scan_delete_group.add_argument("-si", metavar="--scan-id", action="store",help="Scan ID")
scan_delete_group.add_argument("-ssi", metavar="--subscan-id", action="store",help="Sub-scan ID")
##list
scan_list_parser.add_argument("-pn", metavar="--slug", action="store",help="Project name / slug")
##start
scan_start_parser.add_argument("-pn", metavar="--slug", action="store",help="Project name / slug", required=True)
scan_start_parser.add_argument("-ti", metavar="--target-id", action="store",help="Target ID", required=True)
scan_start_parser.add_argument("-ei", metavar="--engine-id", action="store",help="Engine ID", required=True)
##stop
scan_stop_group = scan_stop_parser.add_mutually_exclusive_group(required=True)
scan_stop_group.add_argument("-si", metavar="--scan-id", action="store",help="Scan ID")
scan_stop_group.add_argument("-ssi", metavar="--subscan-id", action="store",help="Sub-scan ID")
##status
scan_status_parser.add_argument("-pn", metavar="--slug", action="store",help="Project name / slug", required=True)
##listvulns
scan_listvulns_parser.add_argument("-si", metavar="--scan-id", action="store",help="Scan ID", required=True)
##listIPs
scan_listips_parser.add_argument("-si", metavar="--scan-id", action="store",help="Scan ID", required=True)
##listScanLogs
scan_listscanlogs_parser.add_argument("-si", metavar="--scan-id", action="store",help="Scan ID", required=True)
scan_listscanlogs_parser.add_argument("-wo", action="store_true",help="Print command output", required=True)
##listTechnology
scan_listtech_parser.add_argument("-si", metavar="--scan-id", action="store",help="Scan ID", required=True)
##ListPorts
scan_listports_parser.add_argument("-si", metavar="--scan-id", action="store",help="Scan ID", required=True)
##listEndpoints
scan_listeps_parser.add_argument("-si", metavar="--scan-id", action="store",help="Scan ID", required=True)

#Organization
##list
organization_targets_parser.add_argument("-oi", metavar="--organization-id", action="store",help="Organization ID", required=True)
##add
organization_add_parser.add_argument("-on", metavar="--organization-name", action="store",help="Organization Name", required=True)
organization_add_parser.add_argument("-d", metavar="--organization-description", action="store",help="Organization Description", required=True)
organization_add_parser.add_argument("-pn", metavar="--slug", action="store",help="Project Name / Slug", required=True)
organization_add_parser.add_argument("-ti", metavar="--target-ids", action="store",help="Target IDs (seperate multiple with commas)", required=True)
##remove
organization_remove_parser.add_argument("-oi", metavar="--organization-id", action="store",help="Organization ID", required=True)

#User
user_add_parser.add_argument("-u", metavar="--username", action="store",help="New user's name")
user_add_parser.add_argument("-p", metavar="--password", action="store",help="New user's password")
user_add_parser.add_argument("-pn", metavar="--slug", action="store",help="ReNgine Project Name / Slug", required=True)
user_add_parser.add_argument("-r", metavar="--role", action="store",help="New user's role", required=True)

args = main_parser.parse_args()
s: requests.Session
#Authorize
if(args.options == 'authorize'):
    REAuthorize(args)
else:
    s = REAuthorize.getSession()

match args.options.lower():
    case 'target':
        RETarget(args, s)
    case 'scan':
        REScan(args, s)
    case 'engine':
        REEngine(args, s)
    case 'organization':
        REOrganization(args, s)
    case 'project':
        REProject(args, s)
    case 'user':
        REUser(args, s)
    case default:
        #Lets do nothing
        pass