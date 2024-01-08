# rengine-tool
CLI tool for interacting with ReNgine, leveraging the API and web requests

You must use the authorize option first.  Once you are done using the tool, it is highly recommended to delete your authorization with: rengine-tool authorize -d

**GENERAL:**
```
Usage: rengine-tool.py [-h] [-oj] {authorize,target,organization,project,scan,engine} ...

options:
  -h, --help            show this help message and exit
  -oj                   JSON output

options:
  {authorize,target,organization,project,scan,engine}
    authorize
    target
    organization
    project
    scan
    engine
```
**AUTHORIZE**
```
usage: rengine-tool.py authorize [-h] [-b --base-url] [-u --user] [-p --password] [-d]

options:
  -h, --help     show this help message and exit
  -b --base-url  URL (ie: https://localhost/)
  -u --user      ReNgine Username
  -p --password  ReNgine Password
  -d             Deletes your session. You should always do this once finished with the tool
```
**TARGET**
```
usage: rengine-tool.py target [-h] {add,delete,list,list-vulns,list-ips,list-tech,list-ports,list-eps} ...

options:
  -h, --help            show this help message and exit

target_action:
  {add,delete,list,list-vulns,list-ips,list-tech,list-ports,list-eps}
    add                 Add target
    delete              Remove target
    list                List targets
    list-vulns          List target vulnerabilities
    list-ips            List target IPs
    list-tech           List target technologies
    list-ports          List target ports
    list-eps            List target endpoints
```
**ORGANIZATION**
```
usage: rengine-tool.py organization [-h] {add,remove,list,list-targets} ...

options:
  -h, --help            show this help message and exit

organization_action:
  {add,remove,list,list-targets}
    add                 Add organization
    remove              Remove organization
    list                List organizations
    list-targets        List organization targets
```
**SCAN**
```
usage: rengine-tool.py scan [-h] {list,start,stop,delete,status,list-ips,list-eps,list-tech,list-ports,list-vulns,list-scanlogs} ...

options:
  -h, --help            show this help message and exit

scan_action:
  {list,start,stop,delete,status,list-ips,list-eps,list-tech,list-ports,list-vulns,list-scanlogs}
    list                List scans
    start               Start scan
    stop                Stop scan
    delete              Delete scan
    status              Get the status of scans
    list-ips            Get IP Addresses from scan
    list-eps            Get Endpoints from scan
    list-tech           List found technoligies in scan
    list-ports          List found ports in scan
    list-vulns          List scan vulnerabilities
    list-scanlogs       List a scans logs
```
**ENGINE**
```
usage: rengine-tool.py engine [-h] {list} ...

options:
  -h, --help  show this help message and exit

engine_action:
  {list}
```
    list      List engines
