#!/bin/bash


# Student name: Eddie Alon
# Student Code: s8
# Class: TMAGEN77369
# Lecturer: Simon Bar

# The user can insert none, 1 or 2 arguments for the username list and for the password list,
# whether there are two arguments, the first argument must be the username list.
# If the user doesn't use the lists or create new password list, there are default lists next to the project file.
# Use sudo su or enter password when asked in the beginning.

# Function for interactive introducement
INTRODUCING () {
	figlet "SCANVULNS"
}

# Function for extracting all hosts from the net
DISCOVERING_HOSTS () {
        NET=$(ip -4 address | grep eth0 | grep brd | awk '{print $2}') # Using special command for extracting by greps (there is more then on interface - also for bridged)
								       # and awk the net and net mask, in form of net\mask_number_of_binary_digits 
        echo "Report for the net: $NET" > report_file # Adding content to the final report
	echo "" >> report_file
        nmap -sn $NET | grep "Nmap scan report for" | cut -d " " -f5 >> ips_net.txt # Extracting list of all the hosts using grep of -sn flag of nmap
													  # for doing only host discovery without port scan, as if to say
													  # only the hosts that respond to the scan like ping scan
        echo "The hosts in the net:" >> report_file
	echo "" >> report_file
        cat ips_net.txt >> report_file # Adding the list of the hosts to the report file
}

# Function for enumerate the names, OS names and services (banner grabbing) from each host
HOSTS_NAMES_OS_SERVICES () {
	mkdir reports # Creating directory for the reports for each host
	mkdir xmldir # Creating a directory the will include all the xml files of each host. In this way it will be easy to pass all the files in for loop and for order.
	for i in $(cat ips_net.txt) # Pass each line in IP file, meaning in this case each host
	do
		echo "" >> reports/report$i
		echo "The name of host $i:" > reports/report$i # Adding content to each report of each host, using file name with IP so it will be easy in
							       # for loops to go over the files, when going over each line of IPs in ips_net.txt
		echo "" >> reports/report$i
		nmblookup -A $i | sed -n 2p | awk '{print $1}' >> reports/report$i # Extracting the name of each host in turn by awk and sed (the sed taking the
									      	   # second line) on the command nmblookup. It's a tool that use NETBIOS querry
									           # (All the hosts are in the same LAN (without DNS)) so the we can retrieve the
										   # name of each host. Adding it to each report file of each host
		echo "" >> reports/report$i
		echo "The OS of the host is:" >> reports/report$i
		echo "" >> reports/report$i
		sudo nmap -O $i | grep "OS details" >> reports/report$i # Extracting for each host with grep  by nmap with flag -O the operating system of the host. sudo is needed.
		echo "" >> reports/report$i
		echo "The services:" >> reports/report$i
		echo "" >> reports/report$i
		# Bannder grabbing - extracting all the services for open ports in each host, only adding the the important information in the report files, removing the unsignificant lines.
		nmap -sV --open $i | grep -v "Starting Nmap" | grep -v "Nmap scan" | grep -v "submit"  | grep -v "SF" | grep -v "Too many" | grep -v "performed" | grep -v "done" >> reports/report$i
		nmap -sV --open $i -oX xmldir/$i.xml # Now creating inserting the xml files of each banner grabbing (the services) to the xml  directory, using name consist
					             # of the ip of each host that it will be easy to pass and use  all the file in the for loop in VULNERSCAN
						     # and for the flag command in the internal for loop in the ENUMS functions.
	done
}

# Function that add to the each report file of for each host all the vulnerabilities by searchsplloit

VULNERSCAN () {
	for i in $(cat ips_net.txt) # Going over each IP (line) in the file, Passing each xml file name inside the directory and each report file for each host
	do
		echo "" >> reports/report$i
                echo "The vulnerabilities of the host are:" >> reports/report$i
                echo "" >> reports/report$i
		searchsploit --nmap xmldir/$i.xml >> reports/report$i # Adding to each suitable report file of each host the vulnerabilities that searchsploit
								      # find for each xml file of each host in the directory
	done
}

# Function that do brutefoce to each host and retrieving the users and suitable passwords for the first found service  by hydra
ENUMS () {
	USERLISTTRUE=0 # Initiate Variable, whether there is argument of user list - it will be 1.
	ENDPASS=0 # Initiate variable, that will be 1 when the user want to stop adding passwords to the password list that he creates.
	# Creating file of services the will be used by hydra for each host
        echo "ssh" > hydra_services.txt
        echo "postgres" >> hydra_services.txt
        echo "smtp" >> hydra_services.txt
        echo "smb" >> hydra_services.txt
        echo "ftp" >> hydra_services.txt
        echo "irc" >> hydra_services.txt
        echo "mysql" >> hydra_services.txt
	echo "telnet" >> hydra_services.txt
        echo "rdp" >> hydra_services.txt
	touch userlist # There is cp command so must be a file
        touch passlist # There is cp command so must be a file
	echo ""
	echo "Did you insert a user list? Insert yes or no." # This way it will be known which argument was inserted or was not inserted -  username list or/and password list
	read answer # Getting input from the user
	if [ "$answer" == "yes" ] # If user list was specified in the first argument, gtype yes and copy it to userlist (hydra will use it)
	then
		cp ${args[0]} userlist
		USERLISTTRUE=1 # Now knowing there was an argument of username list
	else
		cat username.lst > userlist # If there wasn't username list argument, just use the username list coming with the project file, putting it in the userlist for hydra
	fi
	echo "Did you insert a password list? Insert yes or no." # Checking if there is an argument of password list - argument 1 or 2
	read answer2 # getting input from the user
	if [ "$answer2" == "yes" ] # If there is argument of password file, typing yes
	then
		if [ $USERLISTTRUE -eq 1 ] # Checking if username list argument was typed, if yes, copy the second argument to hydra password file
		then
			cp ${args[1]} passlist
		else
			cp ${args[0]} passlist # If there was no argument of username list, so the password specified must be in the first argument, and copy it to passlist for hydra

		fi
	else
		echo ""
		echo "Do you want to create password file? Insert yes or no." # If no password list was specified in the arguments, now the user can create password list.
		read answer3 # Reading input from the user
	        if [ "$answer3" == "yes" ]
        	then
			while [ $ENDPASS -eq 0 ] # Using while for going at once for adding the first password. If ENDPASS!=0, the user don't want to add anymore password and exiting the while.
			do
				echo ""
                                echo "Add a password:"
                                echo "" 
				read PASSWORD # reading each password in turn 
				echo "$PASSWORD" >> passlist # Adding each password to line in the passlist for hydra
				echo ""
				echo "Do you want to add another password to the list? Insert yes or no." # 
				echo ""
				read answerpass # Reading input from user, whether he want to continue inserting passwords to the password list
				if [ "$answerpass" == "yes" ]
        			then
					continue # Go to the next loop of the while, adding another password.
				else
					ENDPASS=1 # No more password is wanted, now the while will be stopped
				fi
			done
		else # If there is no argument in the arguments and a password was not created, adding the password with the project file to the passlist for hydra
		cat password.lst > passlist
		fi
	fi
	for i in $(cat ips_net.txt) # Loop that will pass each line of the ip file, as if to say each host
	do
		echo "" >> reports/report$i
                echo "The users and the passwords found for host:" >> reports/report$i
                echo "" >> reports/report$i
		for j in $(cat hydra_services.txt) #  Internal loop for passing each line (service) that will be used by hydra - The first found service of 9 for each host 
		do
			GREP_FLAG=$(cat xmldir/$i.xml | grep $j)  # Here because the host ip is part of the name of xml files, causing  easily to move through
								  # xml files in the loops, because the same pattern of directory and name of the xml files,
								  # the change is only the ip. So here Checking if there is a service in the xml file of the host,
								  # if no the GREP_FLAG will be without content, if found it will be with content because the grep
								  # found the service name.
			if [ "$GREP_FLAG" == "" ] # If the flag has no content, the service was not found in the xml file of the host.
			then
				continue # Go to Check the next service or if checked for the host all 9 services, moving to external loop.
			else
				hydra -L userlist -P passlist $i $j | grep -i "host" >> reports/report$i # The service was found and using The hydra command, doing brute force,
												         # going over user list and password list for each host (as $i) and
											      		 # for each service (as $j), finding usernames and suitable passwords
													 # for successed login of the service 
				echo "" >> reports/report$i
				break # After founding a service using by the host, exit from the internal loop and proceeding to the next host
			fi
		done
	done
}

# Function that get an input of host from the user and display the content of report of the specified host
REPORTDISPLAY () {
	echo ""
	echo "Insert IP to show its host report."
	echo ""
	read IP # Getting input of host from the user
	for i in $(cat ips_net.txt) # Going over all the IPs
	do
		if [ "$IP" == "$i" ] # If the IP is equal to one of the host of the net, print report of this host
		then
			cat reports/report$i
		fi
	done
}

#Function that insert all the reports into the final report
CREATEFINALREPORT () {
	# Adding the final report the general statistics
	echo "" >> report_file
	echo "General Statistics:" >> report_file
	echo "" >> report_file
	echo "Number of hosts:" >> report_file
	echo "" >> report_file
	cat ips_net.txt | wc -l >> report_file # Calculating number of hosts
	end_time=$(date +%s) # Insert to variable the time seconds in epoch time of end time
	runtime=$((end_time-start_time)) # Calculating difference of end time and of start time (global variable in the code before calling the MAIN function)
	echo "" >> report_file
	echo "Runtime of the program is:" >> report_file
	echo "" >> report_file
	echo "$runtime seconds" >> report_file # Adding the run time to the final report
	echo "" >> report_file
	echo "" >> report_file
	echo "The reports of each host one after another:" >> report_file
	echo "" >> report_file
	for i in $(cat ips_net.txt) # Adding one after another all the reports of each host (going through each IP)
	do
		cat reports/report$i >> report_file
	done
}

# The primary function to call all the functions, removing the unneeded files and directory and printing the report file
MAIN () {
	INTRODUCING
	DISCOVERING_HOSTS
	HOSTS_NAMES_OS_SERVICES
	VULNERSCAN
	ENUMS
	REPORTDISPLAY
	CREATEFINALREPORT
}
args=("$@") # Command in order to use arguments from the cli and causing to be able to use the arguments in the functions.
start_time=$(date +%s) # Insert to global variable the time seconds in epoch time of start time using in function CREATEFINALREPORT
MAIN
 
