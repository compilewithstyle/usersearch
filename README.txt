A script for the NOC/NSO to use which automates the annoying task of looking up a user. It will also use a time-based binary search to speed the process up enormously as compared to the standard zcat/grep methods.

USAGE:  ./usersearch.pl <timestamp> <ip>




Will connect from JEFE -> SYSLOG and jump through the various logs until a user is found or a portion of the search fails.

The process is as follows:

	TIMESTAMP + EXTERNAL_IP  -->  firewall log  -->  INTERNAL_IP

	TIMESTAMP + INTERNAL_IP  -->  DHCP log  -->  MAC_ADDRESS

	TIMESTAMP + MAC_ADDRESS  -->  controller auth databases  -->  WUSTL_KEY

	WUSTL_KEY  -->  key database  -->  USER_PROFILE


By the end, the name, school, role, and email of the user will be in the profile. Otherwise, it will abort along the way and output where it failed.



NOTE: The huge increase in speed comes from performing a time-based binary search across the firewall and DHCP log lines. This reduces the number of line reads and time comparison from several million to just several. 
