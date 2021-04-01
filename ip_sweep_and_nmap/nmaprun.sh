#!/bin/bash
if [ "$1" == "" ]
then
	echo "You must enter file name to run nmap"
	echo "Syntax: ./run_nmap ip_list.txt"
else
	for ip in $(cat "$1"); do nmap -p 80 -T4 $ip; done 
fi
