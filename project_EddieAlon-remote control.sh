#!/bin/bash
# Credit for Simon Aidrov for the code of part of the first function and part of the second function
function inst() { # Function for installing network of servers tor and starts communication
	          # anonymizing service tor
	echo "[+] Tor service configuration..."
	check=$(dpkg -l | grep "anonymizing overlay network for TCP") # True if in the list of
	# packages there is anonymizing network that is to say tor was installed
	sudo sed -i 's/#dynamic_chain/dynamic_chain/g' /etc/proxychains4.conf 
	# Changing conf file in order to connect proxy servers (server between the local
	# network and the internet) in the same order they appear, skipping dead servers
	sudo sed -i 's/socks4/socks5/g' /etc/proxychains4.conf # Changing conf file in order to use
	# socks5. socks5 is socket - protocol that communicate in our case  with the proxy
	# server, and better then socks4, because it is with authentication and support also
	# UDP from the proxy server
	if [[ -z $check ]] # If check=0 install tor
	then
		apt update -y && apt install tor -y # Updating in order to install tor and
		# installing using -y for installing automatically without interactive
		# questions
		echo "[+] starting tor..."
		service tor start # starting the service tor
	
	else #If tor was installed but checking if there is need of starting tor service
		echo "[+] tor is installed"
		s=$(service tor status | grep exited) # In this case TRUE if in the status of
		# the service tor code was exited, as if to say was started
		if [[ -z $s ]] # If s=0 start service tor
		then
			echo "[+] starting tor..."

			service tor start # Starts service tor
		else
			echo "[+] tor service is running..." # The service tor has been
			# already started
		fi
	fi
	sudo apt-get install ssh # Installing ssh
	sudo apt-get install sshpass # Installing sshpass
}

function anon() { # Function that checking that the proxy server is anonymous - from another
		  # another country than Israel
	echo "[+] Checking anonymous..."
	check_ip=$(proxychains curl -s ifconfig.co/country | grep cf-footer-ip | grep span | cut -d '>' -f 2 | cut -d '<' -f 1) # proxychains means forcing to check only the proxy chains
	# of servers for curl -s that shows information about the connection of all .co.
	# Usually it is easier and just show the country, but with proxychains we need to find
	# the IP and in the next command to find finally the country and -s means silent mode
	# without progress or error printing, means it will be easier to find the IP,
	# Extracting the IP using two grep and cutting the IP from the pattern >IP<
	origin=$(curl -s http://ip-api.com/json/$check_ip | jq -r '.country') # Here finding
	# finally the origin country, again with silent mode, now retrieve from the site ip-api
	# in json view according to the IP we found, and with jq -r we create a list view and
	# printing what is the country from the line with "country": "name of country",
	# automatically print the name of the country.
        if [[ $origin == "Israel" ]] # If the origin is from Israel
        then
                echo "[-] Israeli is found! Bye."
                IPOR0="0" # The origin is Israel - global variable is 0
        else 
                echo "[+] The attacker from $origin"
		IPOR0="$check_ip" # global variable is the IP of the proxy server to notify
		# when its prigin is other than Israel - anonymous, IPOR0 is a global variable
		# in order to use string
        fi
}

function vps() {
	service ssh start # starting ssh service
	read -p "Insert The IP of the remote machine in order to connect via ssh: " IPMACHINE
	sshpass -p 'kali' ssh kali@$IPMACHINE nmap -F $IPOR0 # scan fast - 100 common ports
	# for the proxy server represented by its IP. Doing sshpass which include password and
	# pattern with ssh command and with the query command via ssh, ssh command include
	# username@IP of a machine for "remote" connection.
	sshpass -p 'kali' ssh kali@$IPMACHINE whois $IPOR0 # The same as above, just whois
	# query for our proxy service IP via ssh
	sshpass -p 'kali' ssh kali@$IPMACHINE nmap -sV $IPOR0 # The same as above, just
        # banner grabbing of the server, including software version of the ports via ssh
}
IPOR0="0" # Creating global variable, that will be 0 if the origin is from Israel or the IP if not
function main() {
	inst
	anon
	if [ $IPOR0 != "0" ] # If the origin is not from Israel than IPOR0 is the IP, not 0 
	then
		vps 
	fi
}

main
