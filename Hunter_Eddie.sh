#!/bin/bash

# Student name: Eddie Alon Student Code: s8
# Class: TMAGEN77369
# Lecturer: Simon Bar


# The user need to put link of IOC's as an argument.
# Function for interactive introduction 
INTRODUCING () {
        figlet "Hunting"
}
function NetAn ()
{
	wget -O ioc ${args[0]} # Downlowd the IOC link from the argument and saving it as ioc1
	cat ioc | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > ioc_ip # Taking only IP with its pattern and saving to file.
	cat ioc | grep -oE "http://[a-zA-Z0-9./?=_%:-]*" > ioc_url #  #  Taking  URL with pattern starting with http:// and saving to file
}

# Function for sniffing for saving pcap for extracting files, file for live checking for the next functions
function SNIFFING ()
{
	echo "" > ip.txt
	echo "" > url.txt
	tshark -i any -a duration:30 -w ip.pcap -T fields -e frame.time -e ip.src -e ip.dst -q >> ip.txt & # Doing sniffing for 30 seconeds and saving to pcap
													   # file and with quiet mode filter date amd time,
													   # source and destination ip and saving to file,
													   # and doing it in the background and continue to next commands
													   #  for doing it live.
	tshark -i any -a duration:30 -w url.pcap -T fields -e frame.time -e ip.src -e http.request.full_uri -q >> url.txt & # The same as last command but to field of
															     # full URL and save as another file the pcap
															     # and second file for the filtering for the live process
	echo "sniffing..."
	sleep 2 # For giving time until all the sniffings start
}

# Function for checking whether ip or url used in the network are malicious and saving to log file and alert live
function LOG_AND_LIVE_MAL_IP_URL ()
{
	ln_ip=0 # For checking current line in the file with the fields from the sniffing with the destination ip field.
	ln_url=0 # Same as the last variable but for the file with the fields of the full URL.
	flag_ip=0 # Initiate flag as 0, will stay 0 when IP as long as the same as last malicious destination IP last
	flag_url=0 # Same as last variable, but with URL
	detect_ip=0 # For last destination IP, initiate as 0, for always at the start will be included
	detect_url=0 # same as last variable, but for full URL
	ip_dst=0 # For only destination IP field
	URL=0 # For only URL field
	flag=1 # Intiate flag as 1 for doing the while.
	echo "" > log_ip_true # Creating the log file for malicious ip's
	echo "" > log_url_true # Creating the log file for malicious URL'S
	NET=$(ip -4 address | grep eth0 | grep brd | awk '{print $2}') # Extracting ip of the net with the netmask.
	echo "Hunter started analysis for ip's: $NET" >> log_ip_true # Insert to log file.
	echo "Hunter started analysis for http's: $NET" >> log_url_true # Insert to log file.
	echo "Hunter started analysis: $NET" # Putting also live.
	time_start=$(date +%s) # For stopping the while we will need the start time in epoch time  before starting the while.
	while [ $flag -eq 1 ] # As flag 1 keep doing the while.
	do
		IFS=$'\n' # For all the fields in the files of each packet to be in the same line.
		for i in $(cat ip.txt | awk "NR>$ln_ip") # Going over all fields in each packet with the destination IP, starting only from the line we end in the loop last time
							 # for not checking field we have already checked.
		do
			ln_ip=$(cat ip.txt | wc -l) # Here inserting the current line, that in next loop we will start from here for preventing checking again packets we chacked.
			for j in $(cat ioc_ip) # Going over all the IOC of IP
			do
				ip_dst=$(echo "$i" | awk '{print $7}') # Extracting only field of IP destination.
				if [ "$ip_dst" == "$j" ] # Checking whether destination IP we entered is in the IOC file, meaning malicious
				then
					if [ "$detect_ip" != "$ip_dst" ] # For preventing duplications (there are some packets for the malicious destination IP field),
									 # If the last destination IP is the same with the next one, flag is 0,
									 # and don't alert and log. if different alert and log.
					then
						flag_ip=1
					else
						flag_ip=0
					fi
					if [ $flag_ip -eq 1 ] #  If there is a new malicious destination IP.
					then
						c=$(echo "$i" | awk '{print "At date and time: " $1 " " $2 " " $3 " " $4 " " $5 ": " $6 " accessed " $7}') # Insert to variable
															# the fields of date and time, source ip and the malicious ip.
						echo "Found malicious ip: $c" >> log_ip_true # Insert to log file.
						echo "Found malicious ip: $c" # Alert live
						detect_ip=$ip_dst # Here getting the last malicious IP, checkin in the next loop if the same as next one, for preventing dupplications.
					fi
				fi
			done
		done
		# These loops are with the same functionality as the last ones, just instead of destination IP, there is full URl, and ioc's of URL.
		for k in $(cat url.txt | awk "NR>$ln_url")
		do
			ln_url=$(cat url.txt | wc -l)
			for l in $(cat ioc_url)
			do
				URL=$(echo "$k" | awk '{print $7}')
				if [ "$URL" == "$l" ]
                        	then
					if [ "$detect_url" != "$URL" ]
					then
						flag_url=1
					else
						flag_url=0
					fi
					if [ $flag_url -eq 1 ]
					then
						d=$(echo "$k" | awk '{print "At date and time: " $1 " " $2 " " $3 " " $4 " " $5 ": " $6 " accessed " $7}')
                                		echo "Found malicious URL: $d" >> log_url_true
						echo "Found malicious URL: $d"
						detect_url=$URL
					fi
                        	fi
			done
		done
		time_now=$(date +%s) # Taking the current time in epoch time
		diff_time=$(($time_now-$time_start)) # The seconds from starting the while until now
		if [ $diff_time -gt 30 ] # If we are in the while more than 30 seconds (as the capturing of the sniffings) exitting the while)
		then
			flag=0 # This will cause to exit the while.
		fi
	done
}

# This function check if hashes are malicious, and log and alert live
function LOG_AND_LIVE_FILES ()
{
	tshark -r ip.pcap --export-objects http,dir_ip > /dev/null # Extract all the files of http protocol from the pcap file with the malicious destination
								   # IPs and don't print to the screen, and save in given directory.
	tshark -r url.pcap --export-objects http,dir_url > /dev/null # Same as last command, but with the pcap file with the malicious URLs.
	read -p "Please insert your virustotal API: " API # Inserting your API for the virustotal site.
	for i in $(ls dir_ip) # Going over all the file in the directory with the file from the malicious destination IPs
	do
		size_ip=$(printf '%s' "$i" | wc -c | cut -d ' ' -f1) # Extracting the size of each file, taking the first string that is the size,
								     # even if it has % in the name (the printf %s with apostrophes do it).
		if [ $size_ip -lt 1000000 ] # If the file is less than 1MB 
		then
			hash_ip=($(printf '%s' "$i" | md5sum | awk '{print $1}')) # Extracting the hash of the file, again first string, even if its name is with %
			URL="https://www.virustotal.com/vtapi/v2/file/report?apikey=$API&resource=$hash_ip" # Enter a variable URL for virustotal with API and hash
			RESULT_AVS=$(curl -s $URL) # Check and doing report from virustotal for the hash of each file
			DETECTION_MAL=$(echo $RESULT_AVS | grep "true") # If the report has true string, meaning the file is malicious.
			if [ "$DETECTION_MAL" != "" ] # If there is something in the variable, meaning it has true, then it is malicious.
			then
				echo "$i is malicious" >> log_ip_true # Log the malicious file.
				echo "$i is malicious" # Alert live the malicious file
			else
				echo "File $i is not malicious"
			fi
		fi
	done
	# Same as last loops just with files from the malicious URLs
	for j in $(ls dir_url)
	do
		size_url=$(printf '%s' "$j" | wc -c | cut -d ' ' -f1)
		if [ $size_url -lt 1000000 ]
		then
			hash_url=($(printf '%s' "$j" | md5sum | awk '{print $1}'))
			URL="https://www.virustotal.com/vtapi/v2/file/report?apikey=$API&resource=$hash_url"
			RESULT_AVS=$(curl -s $URL)
			DETECTION_MAL=$(echo $RESULT_AVS | grep "true")
			if [ "$DETECTION_MAL" != "" ]
 			then
				echo "File $j is malicious" >> log_url_true
				echo "File $j is malicious"
			else
				echo "File $j is not malicious"
			fi
		fi
	done
}

# The primary function to call all the functions
MAIN ()
{
        INTRODUCING
	NetAn
	SNIFFING
	LOG_AND_LIVE_MAL_IP_URL
	LOG_AND_LIVE_FILES
}
 
args=("$@") # For giving the capability to use argument.
MAIN

