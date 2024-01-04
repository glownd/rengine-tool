import argparse
import pathlib
import requests
from urllib3.exceptions import InsecureRequestWarning
from getpass import getpass
import pickle
class StrToBytes:
    def __init__(self, fileobj):
        self.fileobj = fileobj
    def read(self, size):
        return self.fileobj.read(size).encode()
    def readline(self, size=-1):
        return self.fileobj.readline(size).encode()
    
class REAuthorize():
    def __init__(self, args:argparse.Namespace):
        if args.d == True:
                self.deleteSession()
        else:
            #Set username & password
            username = self.getUsername(args.u)
            password = self.getPassword(args.p)
            
            #Set URLs
            baseUrl = self.cleanBaseUrl(args.b)
            

            #Start session and authorize
            self.authorize(baseUrl, username, password)

    @staticmethod
    def authorize(baseUrl, username, password):
        try:
            loginUrl = baseUrl + 'login/'
            s = requests.Session()
            s.cookies.set("hostname", baseUrl, domain="local.local")
            r1 = s.get(loginUrl, verify=False)
            csrf_token = r1.cookies['csrftoken']
            r2 = s.post(loginUrl, data=dict(username=username,password=password,csrfmiddlewaretoken=csrf_token,next='/'), headers=dict(Referer=loginUrl), verify=False)
            #Lets make sure everything went okay, and save the session if it has
            if('Invalid username or password.' in r2.text):
                print('Invalid username or password!')
            elif(r2.status_code == 200):
                print("AUTHORIZED - Saving session into .rengineSession file")
                #Save session
                with open('.rengineSession', 'wb') as f:
                    pickle.dump(s, f)
                print("SAVED")
            else:
                print('ERROR AUTHORIZING - Check your username/password and base URL.  Status Code: ' + r2.status_code)
        except Exception as error:
            print('ERROR!')
            print(error)
    @staticmethod
    def deleteSession():
        pathlib.Path.unlink('.rengineSession')
        print('Deleted session -- good on you for great security practices!')

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
    
    @staticmethod
    def cleanBaseUrl(url):
        #Add a forward slash at the end of the base URL if it isn't there to save some users a headache
        if url[-1] != "/":
            url = url + "/"
        return url
    
    @staticmethod
    def getSession() -> requests.session:
         with open('.rengineSession', 'rb') as f:
            session = pickle.load(f)
            return session
         
