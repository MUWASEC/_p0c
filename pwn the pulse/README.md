**PwnTHEPulse**
<pre>
pwnpulse.py : 
CVE-2019-11510 with magic function such as :
+ Version Disclosure
+ Admin Panel Checker
- command :
    hash    = dump system
    plain   = dump data.mdb
    cookies = dump cookies db

bruter_cookies.sh :
What ? u think after dump cookie there's no fun ?
- command :
   ./bruter_cookies.sh log/xxx__cookies.bin https://xxx/

rcepliss.py :
CVE-2019-11539 with retard credential into rce.

cred_extract.sh :
It will parse the credential after dumping hash + plain.
- command :
    ./cred_extract.sh log/xxx__hash.bin log/xxx__plain.bin out.txt
</pre>


##### Credits & Thx for :
* [@OrangeTsai](https://devco.re/blog/2019/09/02/attacking-ssl-vpn-part-3-the-golden-Pulse-Secure-ssl-vpn-rce-chain-with-Twitter-as-case-study/)
