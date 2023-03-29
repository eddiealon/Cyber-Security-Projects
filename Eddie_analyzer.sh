#!/bin/bash

# -------------------------

# Functions:

function MEM() # Function that run operations on the MEM file and saving the important details of them.
{
	cp ${args[1]} $PWD/memdir/filemem # Creating copy of the analyzed file to directory memdir in order that using the file will be suitable to all 
					  # computer, otherwise when being in the directory, we can't reach the file with only $PWD, we will need our
					  # unique path for our computer.
	cd memdir # Getting inside the created directory.
	USER=$(whoami) # Insert the current user name to variable.
        TIME_CREATED=$(date) # Insert the analyzing start time to variable.
        echo "==============================User:$USER============================" > statfile.txt # Insert into first line of the statistics file 
												   # the user name.
        echo "==============================Type:${args[0]}=============================" >> statfile.txt # Insert into second line of the statistics
                                                                                                          # file type - MEM.
        echo -e "===========Created time:$TIME_CREATED============\n\n" >> statfile.txt # Insert into the third line of the statistics file the start time of
                                                                                 # the analysis.
        echo "strings:" >> statfile.txt # Insert the title strings to the statistics file
        strings filemem | grep -e "[a-zA-Z0-9._]\+@[a-zA-Z]\+.com" >> statfile.txt # Inserting strings of emails from the memory file to the statistics file.
        strings filemem | grep -e "([0-9]{1,3}[\.]){3}[0-9]{1,3}" >> statfile.txt # Inserting strings of IP's from the memory file to the statistics file.
	echo -e "\n\nvolatility:" >> statfile.txt # Insert the title volatility to the statistics file
	PROFILE=$(./vol -f filemem imageinfo | grep -i "profile" | awk '{print $4}' | cut -d ',' -f1) >> statfile.txt # Inserting to variable the profile
														      # that was extracted the info of the
														      # memory file. I changes the name
														      # of the  stand alone volatility to
														      # vol and out in in the directory,
														      # that's why it is ./vol
	echo "pstree:" >> statfile.txt
	./vol -f filemem --profile=$PROFILE pstree >> statfile.txt # Showing proceesses by tree
	echo "cmdline:" >> statfile.txt
	./vol -f filemem --profile=$PROFILE cmdline >> statfile.txt # showing paths of processes
	echo "connscan:" >> statfile.txt
	./vol -f filemem --profile=$PROFILE connscan >> statfile.txt # Showing connections that the processes used
	echo "hivelist:" >> statfile.txt
        ./vol -f filemem --profile=$PROFILE hivelist >> statfile.txt # Showing the regigtry hives of the memory file
	echo "hashdump:" >> statfile.txt
	./vol -f filemem --profile=$PROFILE hashdump >> statfile.txt # Showing hash password in the memory
								     # file, none in the example

}

# ~~~~~~~~~~~~~~~~~~~~~~~~~

function HDD() # Function that run operations on the HDD file and saving the important details of them.
{
	cp ${args[1]} $PWD/hdddir/filehdd # Creating copy of the analyzed file to directory memdir in order that using the file will be suitable to all 
                                          # computer, otherwise when being in the directory, we can't reach the file with only $PWD, we will need our
                                          # unique path for our computer.

	cd hdddir # Getting inside the created directory.
	USER=$(whoami) # Insert the current user name to variable.
	TIME_CREATED=$(date) # Insert the analyzing start time to variable.
	echo "==============================User:$USER============================" > statfile.txt # Insert into first line to the statistcs file
												   # the user name.
	echo "==============================Type:${args[0]}=============================" >> statfile.txt # Insert into second line of the statistics
													  # file type - HDD.
	echo -e "===========Created time:$TIME_CREATED============\n\n" >> statfile.txt # Insert into the third line of the statistics file the start time of
										 # the analysis.
	echo "binwalk:" >> statfile.txt # Insert the title binwalk to the statistics file.
	binwalk filehdd >> statfile.txt # Insert the output of binwalk operation to the statistics file.
	echo "foremost:" >> statfile.txt # Insert the title foremost to the statistics file.
        foremost =T -o hello_foremost filehdd >> statfile.txt # Export to directory hello_foremost the files of foremost operation to hdddir and Insert
							      # the output to the statistics file (the output doesn't have a lot of information).
	echo -e "\n\n===Directory hello_foremost with files created by foremost are in $PWD===\n\n" >> statfile.txt # Showing where the formost files that were 
													 # created are. It will be between equation marks
	echo "bulk_extractor:" >> statfile.txt # Insert the title bulk_extractor to the statistics file.
        bulk_extractor -o hello_bulk filehdd >> statfile.txt # Export to directory hello_bulk the files of bulk_extractor operation to hdddir and Insert
                                                             # the output to the statistics file (present some information about the file).
        echo -e "\n\n===Directory hello_bulk with files created by bulk_extractor are in $PWD===\n\n" >> statfile.txt # Showing where the bulk_extractor files that were
												     	   # created are. It will be between equation
													   # marks	
	echo "strings:" >> statfile.txt # Insert the title strings to the statistics file
	strings filehdd | grep -i "microsoft" >> statfile.txt # Inserting strings that with, for example with Microsoft, for checking the environment
							      # of the computer from the hdd file to the statistics file.
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~

function LOG() # Show the statistics file
{
	cat statfile.txt
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~

function HAND() # Function that check validity of both type of file and that the file is a file, if
		# yes, creating a directory (if doesn't exist) and calling a suitable function.
{
	cat ${args[1]} 2> error.txt > /dev/null # Checking the second argument by checking if there is content in the file, the stderr is copied to a file.
						# It will be empty, if there is no error, meaning that cat command worked. If the file is not empty, the
						# file is not valid. Furthermore, in ordet that cat command won't be in the output (working or not working)
						# I put > dev/null.
	if [ ! -s error.txt ] # Checking if the error file is empty, meaning there is no error, and the file is okay.
	then
		if [ ${args[0]} == "mem" ] || [ ${args[0]} == "MEM" ] # Checking the type of file (the first argument), if written type is mem/MEM go, to MEM function.
		then
			if [ ! -d memdir ] # Only If the memory directory doesn't exist, create one, it prevents comments in the output
			then
				mkdir memdir # Creating directory for the analysis of the file from HDD
			fi
			MEM
		elif [ ${args[0]} == "hdd" ] || [ ${args[0]} == "HDD" ] # If written type is hdd/HDD, go to HDD function.
		then
			if [ ! -d hdddir ] # Only If the hdd directory doesn't exist, create one, it prevents comments in the output
			then
				mkdir hdddir # Creating directory for the analysis of the memory file
			fi
			HDD
		else
			echo "Wrong type of file, bye bye" #  The written type is neither HDD nor MEM, exiting the analyzer.
			exit
		fi
	else
 		echo "Invalid file, bye bye" # The file is no valid, exiting the analyzer.
		exit
	fi
}

# -------------------------

args=("$@") # Command in order to use arguments from the cli and causing to be able to use the arguments in the functions.

HAND

LOG

# ------------------------
