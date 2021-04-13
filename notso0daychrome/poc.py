import http.server,socketserver,subprocess,sys
PORT = 8000
handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", PORT), handler) as httpd:
    resp = subprocess.run(['python2', './jstoshellcode.py', sys.argv[1], 'shellcode'], stdout=subprocess.PIPE).stdout.decode('utf-8').strip() # damn i hate python2
    open('shellcode.js', 'wb').write(f'var shellcode={resp};'.encode())
    print("Server started at localhost:" + str(PORT))
    httpd.serve_forever()
