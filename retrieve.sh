#!/bin/bash
# sudo sqlite3 /etc/pihole/gravity.db "DELETE FROM adlist"

# https://github.com/mitchellkrogza/Phishing.Database
PHISHING_BIG_LIST_URL=https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-domains.tar.gz

OUTPUT_DIR=build
OUTPUT_DRY=1

LISTS_FILE=lists.txt
LISTS_DIR=lists

nb_files=0
nb_domains=0
nb_wlisted=0

declare -A domains_black
declare -A domains_white
declare -A groups

if [[ -n $1 ]]; then
  OUTPUT_DRY=$1
fi

if [[ $OUTPUT_DRY == 1 ]]; then
  echo "*** Running script in DRY mode ***"
fi

function clean_directories() {
  if [[ $OUTPUT_DRY == 0 ]]; then
    [ -f lists/black ] || rm -rf lists/black/*
    [ -f lists/white ] || rm -rf lists/white/*
  fi

  [ -f $OUTPUT_DIR ] || rm -rf $OUTPUT_DIR
  [ -d $OUTPUT_DIR ] || mkdir $OUTPUT_DIR
}

function remove_domains_white_from_list() {
  echo "Removing domains from whitelist..."

  for key in "${!domains_white[@]}"; do
    if [[ -n ${domains_black[$key]} ]]; then
      nb_wlisted=$((nb_wlisted+1))
      unset domains_black[$key]
    fi
  done

  echo "Removed $nb_wlisted domains from blacklist"
}

function output_domains_black() {
  echo "Creating files using groups..."

  for key in "${!domains_black[@]}"; do
    hostfile=${domains_black[$key]}

    #echo "Hostfile: $hostfile - Group: ${groups[$hostfile]} - key: $key"
    echo "$key" >> "$OUTPUT_DIR/${groups[$hostfile]}.txt"
  done
}

function retrieve_phishing_list() {
  phishing_hosts="lists/black/list999.txt"

  [ -f phishing ] || rm -rf phishing
  [ -d phishing ] || mkdir phishing

  if [[ $OUTPUT_DRY == 0 ]]; then
    wget -O phishing.tgz $PHISHING_BIG_LIST_URL
    tar -zxvf phishing.tgz -C phishing
    rm -rf phishing.tgz

    cp phishing/ALL-phishing-domains.txt $phishing_hosts
  fi

  rm -rf phishing
  groups[$phishing_hosts]="malicious"
}

function retrieve_hosts_files() {
  while read LINE
  do
    if [[ "$LINE" =~ List\: ]];
    then
      type=($LINE)
      type=${type[2]}

      LISTS_CURRENT_DIR=$LISTS_DIR/$type
      [ -d $LISTS_CURRENT_DIR ] || mkdir -p $LISTS_CURRENT_DIR

      echo "Found list of type: $type (dir: $LISTS_CURRENT_DIR)"
    fi

    if [[ "$LINE" =~ Group\: ]];
    then
      group=($LINE)
      group=${group[2]}
    fi

    if [[ "$LINE" =~ ^http ]] || [[ "$LINE" =~ ^file ]];
    then
      nb_files=$((nb_files+1))
      fname=$(printf "$LISTS_CURRENT_DIR/list%03d.txt" $nb_files)

      if [[ -n $group ]]; then
        groups[$fname]=$group
      fi

      echo -e "Group: $group \t File: $LINE"
      if [[ $OUTPUT_DRY == 0 ]]; then
        if [[ "$LINE" =~ ^http ]]; then
          current_dt= `date +"%Y-%m-%d %T"`
          wget -O $fname $LINE

          sed -i '1 s/^/# Original file:\t $LINE\n/' $fname
          sed -i '2 s/^/# Retrieved on:\t $current_dt\n/' $fname
        else
          LINE_T=${LINE/file\:\/\//}
          cp $LINE_T $fname
        fi
      fi
    fi
  done < $LISTS_FILE
}

function process_line() {
  nb_domains=$((nb_domains+1))
  line_split=($LINE)

  if [[ ${#line_split[@]} > 1 ]]; then
    host=${line_split[1]}
  else
    host=${line_split[0]}
  fi

  #grep -e ^0\.0\.\0\.0\+[[a-Z0-9]]*
  if [[ $host =~ ^0\.0\.0\.0[a-Z0-9] ]]; then
    host=$(echo $host | sed 's/0\.0\.0\.0//g')
  fi

  if [[ $host =~ : ]]; then
    readarray -d ":" -t host_split<<<"$host"
    host=${host_split[0]}
    #echo "Fixed host (removed port): $host"
  fi

  if [[ $host =~ @ ]]; then
    readarray -d "@" -t host_split<<<"$host"
    host=${host_split[1]}
    #echo "Fixed host (removed @): $host"
  fi

  if [[ -n "$host" ]]; then
    #echo $host
    if [[ $CURRENT_FILE =~ white ]]; then
      domains_white[$host]="$CURRENT_FILE"
    else
      domains_black[$host]="$CURRENT_FILE"
    fi
  fi
}

function parse_hosts_files() {
  for CURRENT_DIR in $LISTS_DIR/*
  do
    for CURRENT_FILE in $CURRENT_DIR/*
    do
      echo "Reading $CURRENT_FILE - please wait..."

      while read LINE
      do
        LINE=${LINE##* ( )}	# trim

        if [[ "$LINE" != \#* ]] && [[ -n "$LINE" ]];
        then
          process_line $LINE
        fi
      done < $CURRENT_FILE
    done
  done
}

clean_directories
retrieve_phishing_list
retrieve_hosts_files
parse_hosts_files
remove_domains_white_from_list
output_domains_black

echo "Processing ended:"
echo -e "\tFiles: $nb_files"
echo -e "\tTotal number of domains: $nb_domains (all)"
echo -e "\tDomains => White: ${#domains_white[@]} - Black: ${#domains_black[@]}"

##
# MERGE ALL DOMAINS INTO ONE FILE
#  SORT RESULT
##

printf "# Whitelist domains list\n" > tmp.txt
printf "# Database written on: `date +"%Y-%m-%d %T"`\n" >> tmp.txt
printf "%s\n" "${!domains_white[@]}" >> tmp.txt
#for key in "${!domains_white[@]}"; do
#    echo "$key\n" >> white.txt
#done

sort tmp.txt -o $OUTPUT_DIR/white.txt

printf "# Blacklist domains list\n" > tmp.txt
printf "# Database written on: `date +"%Y-%m-%d %T"`\n" >> tmp.txt
printf "%s\n" "${!domains_black[@]}" >> tmp.txt

sort tmp.txt -o $OUTPUT_DIR/black.txt
rm -rf tmp.txt
