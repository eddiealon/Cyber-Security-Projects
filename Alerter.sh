#!/bin/bash

# Student name: Eddie Alon
# Student Code: s8
# Class: TMAGEN77369
# Lecturer: Simon Bar



# Function for interactive introducement
INTRODUCING () {
        figlet "Alerting"
}

# Function for menu for choosing protocol/s for the honeypot/s
SERIVCE_TO_MONITOR () {
	flag=0 # Initiante the flag
	while [ $flag -eq 0 ] # As long as the flag is 0, keep doing the menu.
	do
		echo "Alerter by honeypot"
		echo "Choose one option:"
		echo "1. SSH"
        	echo "2. FTP"
        	echo "3. SMB"
        	echo "4. Start all services"
		read protocol # The user insert number from the menu for the protocol/s for the honeypot/s
		if [ $protocol -ne 1 ] && [ $protocol -ne 2 ] && [ $protocol -ne 3 ] && [ $protocol -ne 4 ]
		then
			echo "Invalid answer" # If the answer is none from the option, show the menu again.
		else
			flag=1 # If the answer is valid, continuing the program.
		fi
	done

}

# This function will install the pentbox for the honeypot
INSTALLING_HONEYPOT () {
	sudo apt-get install ruby
	git clone https://github.com/royaflash/pentbox.git
	cd pentbox 
	tar -zxvf pentbox-1.8.tar.gz
	cd pentbox-1.8 
	chmod u+x pentbox.rb
}

# The function will start the honeypot/s according to the chosen protocol and log it automatically to log and LIVE
# After you want to stop the listening, press ctrl-c, and then starting the to take the details of the ip-s in the next function.
ALERT_AND_LOG () {
	if [ $protocol -eq 1 ] # If the chosen protocol is SSH, open automatically honeypot for it
	then
		# Inserting 2 for Network tools and then 3 for honeypot, and 2 for manual configuration, and afterwards 22 for port of ssh
		# Then Insert message hi that will deceit the user and then y to log, and enter for saving log file in ~/pentbox/pentbox-1.8/other/log_honeypot.txt"
		# Insert y or n for beep sound, and the intrude through ip:22
		cd ~/pentbox/pentbox-1.8 # For starting pentbox, getting into the right path, and then will be able to run.
		printf '2\n3\n2\n22\nhi\ny\n\ny\n' | ./pentbox.rb # Here the honeypot will start with all the answer above automatically
								  # and be displayed LIVE and be saved to log for port 22 SSH
	elif [ $protocol -eq 2 ] # The same as before, but with port 21 FTP
	then
		cd ~/pentbox/pentbox-1.8
		printf '2\n3\n2\n21\nhi\ny\n\ny\n' | ./pentbox.rb # Inserting 21 as port
        elif [ $protocol -eq 3 ] # The same as before, but with port 445 SMB
        then 
                cd ~/pentbox/pentbox-1.8
                printf '2\n3\n2\n445\nhi\ny\n\ny\n' | ./pentbox.rb # Inserting 445 as port
	else # The same as before, but now starting 3 honeypots for all the protocol simultaneously, logging all of them into one log file
		cd ~/pentbox/pentbox-1.8
		printf '2\n3\n2\n22\nhi\ny\n\ny\n' | ./pentbox.rb & # Starting honeypot for SSh and taling it to background (still listening) in order that the next honeypot could start
		sleep 5 # For giving time for all the answers is being inserted, and starting the last honeypot cleanly
		printf '2\n3\n2\n21\nhi\ny\n\ny\n' | ./pentbox.rb & # The same as before, but now the honeypot listen with port 21 FTP
		sleep 5 # Again wating 5 seconds
		printf '2\n3\n2\n445\nhi\ny\n\ny\n' | ./pentbox.rb # Now creating honeypot for SMB, and all 3 honeypot listen to SSH, FTP and SMB.
	fi

}

# This time the function will save to a file all the wanted details of each IP that intrude the honeypot.
LOG_DETAILS () {
	cd ~ # Return for the path that the file of the detail will be saved.
	mkdir xmldir # Creating a directory for saving the xml files for order and going cleanly through the for loop
	echo "" > ips_scan.txt # Creating the file for saving the details
	cat ~/pentbox/pentbox-1.8/other/log_honeypot.txt | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq > ips.txt # Taking only the IPs with right pattern, and only each one of them
															      # and saving them to file
	for i in $(cat ips.txt) # Going through all the ips in the file
	do
		echo "Information for IP $i:" >> ips_scan.txt
		echo "" >> ips_scan.txt
		whois $i | grep -i 'country:\|organization:\|orgabuse' >> ips_scan.txt # Saving the origin country, organization and contact information of each ip to the file by grepping whois
		echo "" >> ips_scan.txt
		echo "Open services and ports:" >> ips_scan.txt
		nmap -p- -sV $i --open | grep -v 'Nmap\|shown\|Host' >> ips_scan.txt # Saving for each ip open ports and their services without unnecessary lines to file.
		nmap -p- -sV $i -oX xmldir/$i.xml # Creating xml files by output of nmap scan of services for each ip.
		echo "" >> ips_scan.txt
                echo "searchsploits results:" >> ips_scan.txt
		searchsploit -v --nmap xmldir/$i.xml >> ips_scan.txt # Doing searchsploit for each xml file of each ip
		echo "" >> ips_scan.txt
	done
	cat ips_scan.txt
}

# The primary function to call all the functions
MAIN () {
	INTRODUCING
	SERIVCE_TO_MONITOR
	# INSTALLING_HONEYPOT
	ALERT_AND_LOG
	LOG_DETAILS
}

protocol=0 # Global variable for the function ALERT_AND_LOG to use it from the answer from function SERVICE_TO_MONITOR

MAIN
