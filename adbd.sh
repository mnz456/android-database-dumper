#!/bin/bash
# Android database dumper alpha - Proof of concept
# cam1235(at)port(dot)ac(dot)uk - Ben Harrison-Smith
# The University of Portsmouth
# Digital Forensics - DFIR Year 3
# -Requires andriod SDK in current dir

echo -e "       \n### Android database dumper ###"
echo -e "Note: This application accesses the devices Sdcard\nTake required precautions!\n"
echo "===================================================="
if [ "$(which expect)"  == '' ] 
then
	echo "No expect package found!"
	sudo apt-get install expect
	echo -e "\Please restart the application to continue..\n"
	exit 1
else

# Check adb and expect srcipt in dir
if [ ! -e adb ] 
then
	echo -e "\nError: adb not found in current dir!\n Please update your sources..\n"  
	exit 1
fi
if [ ! -e gendb_expect ] 
then
	echo -e "\nError: gendb_expect not found in current dir!\n Please update your sources..\n"  
	exit 1
fi

insp=
caseno=
wrkdir=
# Case setup
while [[ "$insp" || "$caseno" || "$wrkdir" == "" ]]; do
	echo -n "Enter examiner reference: " 
	read insp
	echo -n "Enter case no.: " 
	read caseno 
	echo -n "Enter working directory: " 
	read wrkdir
	if [[ "$insp" || "$caseno" || "$wrkdir" == "" ]]
	then
		echo "Null variable detected, relooping.."
		break
	fi
	echo "===================================================="
done

while [ -e $wrkdir ]; do
	echo -n "$wrkdir already exists, please choose an empty dir"
	read wrkdir
done
# add / if missing
if [ $(echo $wrkdir | sed -e 's/^.*\(.\)$/\1/') != "/" ]
then
	wrkdir=$wrkdir/
fi
mkdir -p $wrkdir$caseno

echo -e "Creating report file ("$caseno".log)"
echo "Android database dumper report: " > $caseno.log
date | tee -a $wrkdir$caseno/$caseno.log
echo "Examiner: "$insp | tee -a $wrkdir$caseno/$caseno.log
echo "Case: "$caseno | tee -a $wrkdir$caseno/$caseno.log
echo "Output: "$wrkdir | tee -a $wrkdir$caseno/$caseno.log

# Check phone state
echo -e "\nChecking for connectivity.."
devstatus="$(./adb get-state)"
if [ $devstatus == "unknown" ] 
then
	echo "## Error: No device found, please ensure the device is connected and try again ##" | tee -a $wrkdir$caseno/$caseno.log
	exit 1
fi
echo -e "\n## Device(s) found! ##"
./adb devices | tee -a $wrkdir$caseno/$caseno.log
echo -n "Remounting..."
./adb remount

# Use of expect due to bash formatting issues when piping from
# adb console - ./adb shell find /data -name *.db > out.txt (erroneous)

# Find databases
echo -e "\n## Searching device for .db files ##"
expect -f gendb_expect
echo "Pulling directory listing.."
./adb pull /sdcard/gendb.txt gendb.txt | tee -a $wrkdir$caseno/$caseno.log

# make secure tmp dir
sectmp=$caseno$RANDOM
trap 'echo -e "\nTrapped exit signal, cleaning up.." | tee -a $wrkdir$caseno/$caseno.log ; ./adb shell rm -rf /sdcard/$sectmp/ ; exit'  INT
count="$(cat gendb.txt | wc -l)"

echo -e "\n## Processing "$count" databases.. ##"
cat gendb.txt | while read line
	do
		devstatus="$(./adb get-state)"
		if [ $devstatus == "unknown" ] 
		then
			echo "## Error: Device disconnected! Quiting.. ##" | tee -a $wrkdir$caseno/$caseno.log
			exit 1
		fi
		x=`expr $x + 1`
		echo
		echo "Extracting database "$x" of "$count".."
		trunc=` echo $sectmp$line | sed 's/[^\/]\+$//' `
		echo -n $line | tee -a $wrkdir$caseno/$caseno.log
		./adb shell mkdir -p /sdcard/$trunc
		./adb shell md5sum $line >> $wrkdir$caseno/original.md5
		./adb shell dd if=$line of=/sdcard/$sectmp$line >> $wrkdir$caseno/$caseno.log
		mkdir -p $wrkdir$caseno
		./adb pull /sdcard/$sectmp$line $wrkdir$caseno$line >> $wrkdir$caseno/$caseno.log
		md5sum $wrkdir$caseno$line >> $wrkdir$caseno/extracted.md5
	done

# Cleanup
echo "Removing temp file stores.."
./adb shell rm -rf /sdcard/$caseno/
./adb shell rm /sdcard/gendb.txt
mv gendb.txt $wrkdir$caseno/filelist.txt

# Checksum matching
echo -e "\n## Checking md5 pairs.. ##"
ext="$(diff <(cut -d " " -f1 $wrkdir$caseno/original.md5) <(cut -d " " -f1 $wrkdir$caseno/extracted.md5) | cut -d " " -f2 | sed -n '/1c1/,/---/p' | sed -e '2,$!d' -e '$d')"

if [ "$ext" == "" ]
then
	echo "All sums matched.. Extracted file integrity ok!" | tee -a $wrkdir$caseno/$caseno.log
else
	echo $ext | while read cksum
		do
			echo -n "# Alert: Unmatched m5dpair in extracted file " | tee -a $wrkdir$caseno/$caseno.log		
			grep $cksum $wrkdir$caseno/original.md5 | sed 's/.*\///' | tee -a $wrkdir$caseno/$caseno.log		
		done
fi

# Lock files as read only
chmod 444 $wrkdir$caseno/*
echo -e "\nReport generated: "$wrkdir$caseno"/"$caseno".log"
echo "Summary: "$count" databases extracted" | tee -a $wrkdir$caseno/$caseno.log
echo "exiting.."
echo
fi
