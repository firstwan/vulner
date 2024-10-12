#!/bin/bash

#################################################################
# Bash Name: Info Extractor					                    #
# Author: Wan Siew Yik						                    #
# Student Code: s4                                        	    #
# Unit Code: CFC060524                                  	    #
# Tutor Name: Samson                            	       	    #
#################################################################

# Options configuration variable
OUTPUT_DIR=""
TARGET=""
USER_WORDLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PASS_WORDLIST="/usr/share/seclists/Passwords/xato-net-10-million-passwords-100.txt"
FULL_MODE=false
ZIP_RESULT=false
UDP_SCAN=true

DB_NAME=vuln.db

# Function to precess installationprocess
function installRequiredPackage {
    case $1 in
        *)
            local package_status
            package_status=$(dpkg-query -W -f='${Status}' $1 2>/dev/null | grep "install ok installed")
            if [[ "" = $package_status ]]
            then
                echo "[#] Installing $1..."
                sudo apt-get install -y $1 >/dev/null 2>&1
            fi
        ;;
    esac
    echo "[#] $1 has been installed."
}

# Function to show available options
function usage {
    echo -e "Usage: $0 [options] <TARGET>"
    echo 
    echo "Required arguments:"
    echo -e "<TARGET> Domain or IP address target to run the scan"
    echo 
    echo "Options:"
    local options="-h, |--help | | Help menu \n"
    options+="-d | | [NAME] | Specific the directory where to store the scan result \n"
    options+="-f | | | Turn on full mode, which included vulnerability scan \n"
    options+="-u, |--user | [File] | Specific user wordlist to use \n"
    options+="-p, |--pasword | [PATH] | Specific password wordlist to use \n"
    options+=" |--skip-udp | | Indicate to skip UDP scan \n"
    options+="-z | | | Zip the folder before exit \n"
    echo -e $options | column -t -s "|"
}

# Function to show interactive usage
function interactiveUsage {
    echo "[#] Usage:"
    usage="[#] help|Display this usage menu\n"
    usage+="[#] hosts|Display all host data\n"
    usage+="[#] ports <Host's IP>|Display all ports belong to host\n"
    usage+="[#] creds <Host's IP>|Display all found credential belong to host\n"
    usage+="[#] tables|Display the DB tables' structure\n"
    usage+="[#] <SQL SELECT statement>|Run the SQL statement to query data\n"

    echo -e $usage | column -t -s "|"
}

# Function to display DB table structure
function db_structure {
    echo "======================"
    echo "|        hosts       |"
    echo "======================"
    echo "id"
    echo "ip_address"
    echo "======================"
    echo
    echo "======================"
    echo "|        ports       |"
    echo "======================"
    echo "id"
    echo "protocol"
    echo "port_num"
    echo "service_name"
    echo "version"
    echo "======================"
    echo
    echo "======================"
    echo "|     found_cred     |"
    echo "======================"
    echo "id"
    echo "user"
    echo "password"
    echo "======================"
    echo
}

# Create a DB for user to do searching later
function db_creation {
    sqlite3 $DB_NAME  "CREATE TABLE IF NOT EXISTS hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT, UNIQUE(ip_address));"
    sqlite3 $DB_NAME  "CREATE TABLE IF NOT EXISTS ports (id INTEGER PRIMARY KEY AUTOINCREMENT, protocol TEXT, port_num INTEGER, service_name TEXT, version TEXT, host_id INTEGER, FOREIGN KEY(host_id) REFERENCES hosts(id), UNIQUE(host_id, protocol, port_num));"
    sqlite3 $DB_NAME  "CREATE TABLE IF NOT EXISTS found_cred (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, password TEXT, host_id INTEGER, FOREIGN KEY(host_id) REFERENCES hosts(id), UNIQUE(host_id, user, password));"
}

# Function to insert host data
function insert_host_data {
    sqlite3 $DB_NAME  "INSERT OR IGNORE INTO hosts(ip_address) VALUES('$1')"
}

# Function to insert port data
function insert_port_data {
    local protocol=$(echo $1 | cut -d '|' -f 1)
    local port_num=$(echo $1 | cut -d '|' -f 2)
    local service_name=$(echo $1 | cut -d '|' -f 3)
    local version=$(echo $1 | cut -d '|' -f 4)
    local host_id=$(sqlite3 $DB_NAME "SELECT id FROM hosts WHERE ip_address='$2';")
    sqlite3 $DB_NAME  "INSERT OR IGNORE INTO ports(protocol, port_num, service_name, version, host_id) VALUES('$protocol', '$port_num', '$service_name', '$version', $host_id)"
}

# Function to insert found credential data
function insert_found_cred_data {
    local user=$(echo $1 | cut -d " " -f 6)
    local password=$(echo $1 | cut -d " " -f 8)
    local host_id=$(sqlite3 $DB_NAME "SELECT id FROM hosts WHERE ip_address='$(echo $1 | cut -d " " -f 4)';")
    sqlite3 $DB_NAME  "INSERT OR IGNORE INTO found_cred(host_id, user, password) VALUES($host_id, '$user', '$password')"
}

# Function to query data
function query_data {
    sql_statement=$1
    shift
    sqlite3 $DB_NAME "$sql_statement" $@
}

# Function to parse Nmap result
function parseNmapXML {
    xml_file=$1

    # Get all host
    hosts=$(xmlstarlet sel -t -m "//hosthint/address[@addrtype='ipv4']" -v "@addr" -n $xml_file)

    # Get all the port of the host
    for host in $hosts; do
        insert_host_data $host
        ports=$(xmlstarlet sel -t -m "//host/address[@addr='$host']/../ports/port" -v "concat(@protocol, '|', @portid, '|')" \
                --if 'not(boolean(./service))' \
                    -o 'null|null|' \
                --else \
                    -m "service" -v "concat(@name,'|')"  \
                    --if 'boolean(@version)' -v "concat(@version, '|')" \
                        --else -o 'null|' \
                -b \
                -n $xml_file)
        while read port; do
            if [ ! -z "$port" ]; then
                insert_port_data "$port" $host
            fi
        done <<< $ports
    done
}

# Function to check is it have weak password applied
function checkWeakPassword {
    local hosts=$(query_data "SELECT id, ip_address FROM hosts;")

    for host in $hosts; do
        # Check which service is available to exploit
        local host_id=$(echo $host | cut -d '|' -f 1)
        local host_ip=$(echo $host | cut -d '|' -f 2)
        local target_service="'ssh', 'rdp', 'telnet', 'ftp'"
        local services=$(query_data "SELECT port_num, service_name 
                FROM ports
                WHERE service_name in ($target_service) 
                    AND host_id = $host_id
                limit 1")
        local hydra_cmd=""

        if [ ! -z "$services" ]; then
            local port=$(echo $services | cut -d '|' -f 1 )
            local service_name=$(echo $services | cut -d '|' -f 2 )

            hydra_cmd="$service_name://$host_ip -s $port"

            local hydra_output_file="found_password.txt"
            # Find weak credential with hydra
            echo "[#] Attacking $service_name://$host_ip:$port..."
            hydra -L $USER_WORDLIST -P $PASS_WORDLIST $hydra_cmd -I -o $hydra_output_file &>/dev/null
        fi
    done

    # Read all found password
    while read line; do
        if [ ! -z "$line" ]; then
            insert_found_cred_data "$line"
        fi
    done <<< $(cat $hydra_output_file | sed '/#/d' | tr -s '[]' ' ')
}

# Function that generate summary for a host
function generateSummary {
    local host_id=$(echo $1 | cut -d "|" -f 1)
    local host_ip=$(echo $1 | cut -d "|" -f 2)

    portsBody=$(query_data "SELECT protocol, port_num, service_name, version 
                            FROM ports
                            WHERE host_id = $host_id")

    credentialBody=$(query_data "SELECT user, password 
                            FROM found_cred
                            WHERE host_id = $host_id")

    echo "#####################################" | tee -a summary.txt
    printf "# Discovered hosts: %-15s #\n" $host_ip | tee -a summary.txt
    echo "#####################################" | tee -a summary.txt

    echo -e "Open Ports:" | tee -a summary.txt
    column -t -L -s '|' <<< $portsBody | tee -a summary.txt
    echo "" | tee -a summary.txt
    echo -e "Found credentials:" | tee -a summary.txt
    column -t -L -s '|' <<< $credentialBody | tee -a summary.txt
    echo "" | tee -a summary.txt
}

# Find out the script for assetment
function vulnerabilityScan {
    local hosts=$(query_data "SELECT id, ip_address FROM hosts")

    for host in $hosts; do
        local host_id=$(echo $host | cut -d '|' -f 1)
        local host_ip=$(echo $host | cut -d '|' -f 2)
        local services=$(query_data "SELECT port_num, service_name, version 
                FROM ports
                WHERE host_id = $host_id")

        # List out the service that can execute assessment one by one
        while read -u 3 service; do
            if [ ! -z "$service" ]; then
                local port_num=$(echo $service | cut -d '|' -f 1)
                local service_name=$(echo $service | cut -d '|' -f 2)

                # Search the available scanner script
                local scanner_dir="/usr/share/metasploit-framework/modules/auxiliary/scanner/$service_name/"
                
                if [ -d $scanner_dir ]; then
                    scanner_scripts=$(ls /usr/share/metasploit-framework/modules/auxiliary/scanner/$service_name/)

                    # Only perform the assessment if found any script
                    if [[ $scanner_scripts != "" ]]; then
                        # Let user decide to execute the assessment or not
                        local action=""
                        while [[ ${action,,:0:1} != 'y' && ${action,,:0:1} != 'n'  ]]; do
                            echo "[#] Found $host_ip running $service_name service on port $port_num."
                            read -p "[?] Do you want to run vulnerability scanning ? [Default: N] [Y/N] " action
                            echo

                            case "${action:0:1}" in
                                y|Y)
                                    # Insert all the script into array
                                    local selected_script=0
                                    scripts=()
                                    for item in $scanner_scripts; do 
                                        scripts+=($(echo $item | sed -e 's/\..*$//g'))
                                    done

                                    # Display the selection for user choose which to run
                                    while [[ $selected_script < 1 || $selected_script > ${#scripts[@]} ]]; do
                                        for (( index=1; index <= ${#scripts[@]}; index++)); do
                                            echo "$index) ${scripts[(($index-1))]}"
                                        done
                                        echo
                                        read -p "[?] Select which script to use [num] > " selected_script
                                        echo
                                        if [[ $selected_script < 1 || $selected_script > ${#scripts[@]} ]]; then
                                            echo "[!] Index out of bound, kindly select available index only."
                                            echo
                                        fi
                                    done

                                    # Run the msfconsole, select the module, and set the host IP and port
                                    echo "[#] Running Msfconsole to run the scan."
                                    echo "[#] Module to use: auxiliary/scanner/$service_name/${scripts[$(($selected_script-1))]}"
                                    msfconsole -n -q -x "use auxiliary/scanner/$service_name/${scripts[$(($selected_script-1))]}; set rhosts $host_ip; set rport $port_num; run;exit"
                                    echo
                                ;;
                                ""|n|N)
                                    action="n"
                                ;;
                                *)
                                    echo "[!] Invalid option."
                                ;;
                            esac
                        done
                    fi
                fi
            fi
        done 3<<< $services
    done
}

# Check if any arguments pass in
if [[ $# -eq 0 ]]; then
  usage
  exit
fi

# Set up to accept long options
args=$(getopt -a -o fd:hu:p:z --long full,directory:,help,user:,password:,skip-udp -- "$@")
set -- ${args}

# Modify the default setup based on options input
while :
do
    case $1 in
        -f|--full)
            # Enable full mode
            FULL_MODE=true
            shift
            ;;
        -d|--directory)
            OUTPUT_DIR=$(echo $2 | sed "s/'//g")
            shift 2
            ;;
        -h|--help)
            usage
            exit
            ;;
        -u|--user)
            # Specific user wordlist path
            USER_WORDLIST=$2
            shift 2
            ;;
        -p|--password)
            # Specific password wordlist path
            PASS_WORDLIST=$2
            shift 2
            ;;
        --skip-udp)
            # Specific to skip udp scan
            UDP_SCAN=false
            shift
            ;;
        -z|--zip)
            ZIP_RESULT=true
            shift
            ;; 
        --)
            shift 
            break
            ;;
        *)
            echo "[#] Invalid options"
            usage exit
            ;;
    esac
done

TARGET=$(echo $1 | sed "s/'//g")

# IP regex validation
IP_REG="^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))(\/(1?[1-9]|2[0-4]))?$"
if [[ ! $TARGET =~ $IP_REG ]]; then
    echo "[!] Invalid IP address."
    exit
fi    

# Wordlist path validation
if [ ! -f $USER_WORDLIST ]; then
    echo "[!] Invalid user wordlist. Unable to find user wordlist."
    exit
elif [ ! -f $PASS_WORDLIST ]; then
    echo "[!] Invalid password wordlist. Unable to find password wordlist."
    exit
fi

# Set directory as target if no specific
if [ -z "$OUTPUT_DIR" ]; then
    # Use sed to sensitized the ip
    OUTPUT_DIR=$(echo $TARGET | sed -E 's/\//_/g')
fi

# Install required package
APP_TO_INSTALL=("seclists sqlite3 hydra zip")

echo "[#] Updating package repo...."
sudo apt-get update > /dev/null 2>&1

for str in $APP_TO_INSTALL
do
    installRequiredPackage $str
done

echo

# Create output directory
mkdir -p $OUTPUT_DIR
cd $OUTPUT_DIR

# Database creation
echo -e "[#] Initiating DB..."
db_creation

# Nmap scaning
echo -e "[#] Scanning the network $TARGET...."
file_name=nmap_scanning
echo "[#] Scanning for TCP...."
sudo nmap $TARGET -sV -sT -oN $(echo $file_name)_tcp.txt -oX $(echo $file_name)_tcp.xml &>/dev/null
if $UDP_SCAN; then
    echo "[#] Scanning for UDP...."
    sudo nmap $TARGET -sV -sU -oN $(echo $file_name)_udp.txt -oX $(echo $file_name)_udp.xml &>/dev/null
fi

# Nmap parse
echo -e "[#] Organizing the Nmap result."
parseNmapXML $(echo $file_name)_tcp.xml

if $UDP_SCAN; then
    parseNmapXML $(echo $file_name)_udp.xml
fi

echo

# Check weak password
echo -e "[#] Checking if any weak password used..."
echo -e "[#] User wordlist: $USER_WORDLIST"
echo -e "[#] Password wordlist: $PASS_WORDLIST"
checkWeakPassword

echo 

# Generate summary
hosts=$(query_data "SELECT id, ip_address FROM hosts")
while read host; do
    generateSummary $host
done <<< $hosts

echo

# Vulnerability scan
if $FULL_MODE ; then
    echo "[#] Vulnerability scan"
    vulnerabilityScan
fi

echo

# Interactive stage
echo "[#] Interactive stage"
interactiveUsage
action=""

while [[ $action != "q" || $action != "quit" ]]; do
    echo
    read -p "[?] Enter SQL SELECT statement to query the DB or 'help' to show available usage or 'q' to quit: " action
    echo

    if [[ ${action,,} == "select"* ]]; then
        query_data "$action" -column -header
    elif [[ ${action,,} == "quit" || ${action,,} == "q" ]]; then
        echo "Bye bye!"
        break
    elif [[ ${action,,} == "help" ]]; then
        interactiveUsage
    elif [[ ${action,,} == "tables" ]]; then
        db_structure
    elif [[ ${action,,} == "hosts" ]]; then
        query_data "SELECT ip_address from hosts" -column -header
    elif [[ ${action,,} == "ports"* ]]; then
        query_data "SELECT P.protocol, P.port_num, P.service_name, P.version 
                    FROM ports P 
                    INNER JOIN hosts H on H.id=P.host_id 
                    WHERE H.ip_address='$(echo $action | cut -d " " -f 2)'" -column -header
    elif [[ ${action,,} == "creds"* ]]; then
        query_data "SELECT C.user, c.Password 
                    FROM found_cred C 
                    INNER JOIN hosts H on H.id=C.host_id 
                    WHERE H.ip_address='$(echo $action | cut -d " " -f 2)'" -column -header
    else
        echo "Invalid command, kindly use 'help' command to check available usage."
    fi
done


if $ZIP_RESULT; then
    echo
    echo "[#] Process to zip the folder..."
    cd ..
    zip -r $OUTPUT_DIR.zip $OUTPUT_DIR &>/dev/null
    echo "[#] Done zip the folder."
fi
