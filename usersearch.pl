#!/usr/bin/env perl

use strict;
use warnings;
use feature 'say';
use Date::Parse;
use Net::OpenSSH;
use DateTime;
use XML::Simple;
use Data::Dumper;

#----------------------------------------------------------------------------------
my $debug = 0;

# redact info, keep in root read-only files
chomp( my $pw = `cat ./keys/pw` );
chomp( my $mac_lookup = `cat ./keys/mac_lookup` );
chomp( my $key_lookup = `cat ./keys/key_lookup` );
#----------------------------------------------------------------------------------

sub abort {
	my $msg = shift;
	print "ABORT: $msg\n"; exit;
}

sub debug {
	my $msg = shift;
	print "DEBUG: $msg\n"  if $debug;
}

# use the given timestamp and internal IP to find relevant firewall log lines
#
sub fetch_firewall_log($$$) {
	my ($ssh_conn, $ts, $ip) = @_;

	# using the log creation date, determine which log would contain the info
	foreach( $ssh_conn->capture("ls -ltr /var/log/firewall*") ) {
		( my $log_ts ) = /(\d{4}\-\d{2}\-\d{2} \d{2}:\d{2})/;
		if ( $ts - str2time($log_ts) < 0 ) {
			# zcat the log file over SSH and grep out relevant lines
			/(?<log>\/var\/log\/firewall\S+)/;
			debug("Retreving firewall log... ");
			my @lines = $ssh_conn->capture("zcat -f $+{log} | grep translation | grep Built | grep $ip");
			debug("done\n");
			return \@lines;
		}
	}
	
	abort("Couldn't find firewall log.");
}

# use the given timestamp and internal IP to find relevant infoblox log lines
#
sub fetch_infoblox_log($$$) {
	my ($ssh_conn, $ts, $ip) = @_;

	# using the log creation date, determine which log would contain the info
	foreach( $ssh_conn->capture("ls -ltr /var/log/infoblox*") ) {
		( my $log_ts ) = /(\d{4}\-\d{2}\-\d{2} \d{2}:\d{2})/;
		if ($ts - str2time($log_ts) < 0 ) {
			# zcat the log file over SSH and grep out relevant lines
			/(?<log>\/var\/log\/infoblox\S+)/;
			debug("Retreving infoblox log... ");
			my @lines = $ssh_conn->capture("zcat -f $+{log} | grep DHCPACK | grep $ip");
			debug("done\n");
			return \@lines;
		}
	}
	
	abort("Couldn't find infoblox log.");
}

# set up the firewall lines for a binary search to find the internal IP
#
sub find_internal_ip {
	my @lines = @{shift @_};
	my ($ts, $ip) = @_;

	# map timestamp -> remainder of line
	my %timemap = map { substr($_, 0, 15) => $_ } @lines;

	# sort the map by time
	my @sorted_times = sort(keys %timemap);

	## determine which line is closest
	my $index = binary_search(\@sorted_times, $ts, 0);

	abort("Couldn't find internal IP.") unless defined $index;

	# pull out the ips and determine which one corresponds to external
	my @ips = $timemap{$index} =~ /\d+\.\d+\.\d+\.\d+/g;
	foreach( @ips ) {
		return $_ if $_ ne $ip;
	}
}

# set up the infoblox lines for a binary search to find the mac address
#
sub find_mac_addr {
	my @lines = @{shift @_};
	my ($ts, $ip) = @_;

	# map timestamp -> remainder of line
	my %timemap = map { substr($_, 0, 15) => $_ } @lines;

	# sort the map by time
	my @sorted_times = sort(keys %timemap);

	# determine which line is closest
	my $index = binary_search(\@sorted_times, $ts, 0);

	abort("Couldn't find mac address.") unless defined $index;
	
	# pull out mac address
	$timemap{$index} =~ /((?:\w{2}:){5}\w{2})/;
	return $1;
}

# recursive binary search to help search for closest timestamp
#
sub binary_search {
	my @a = @{ shift @_ };
	my $ts = shift;
	my $count = shift;
	
	$count++;
	
	my $i = int(scalar @a / 2);
	
	if( scalar @a < 10 ) {
		return undef if scalar @a == 0;
		debug("Short-circuiting after $count recursions.\n");
		my %hash = map { abs ($ts - str2time($_)) => $_ } @a;
		return $hash{(sort(keys(%hash)))[0]};
	}

	my $timediff_up = abs( $ts - str2time($a[$i]) );
	my $timediff_down = abs( $ts - str2time($a[$i-1]) );
	
	if( $timediff_down >= $timediff_up ) {
		@a = splice(@a, $i);
		return binary_search(\@a, $ts, $count);
	} else {
		@a = splice(@a, 0, $i);
		return binary_search(\@a, $ts, $count);
	}
}

sub fetch_wustl_key($$$) {
	my ($ssh_conn, $ts, $mac) = @_;

	# convert epoch time to DateTime object to generate ctrlsearch time
	my $dt = DateTime->from_epoch(epoch => $ts);
	my $ctrlsearch_time = sprintf "%s-%s-%s %s:%s:%s:00",
		$dt->year,
		$dt->month,
		$dt->day,
		$dt->hour,
		$dt->minute,
		$dt->second;

	# try various methods for wustl key until one (hopefully) works
	my $wustl_key = undef;
	if( !defined $wustl_key ) {
		my $lookup = `curl -ssl3 -k -u nso:$pw -X GET $mac_lookup -d mac~=$mac`;
		$wustl_key = $1 if $lookup =~ /"username":\s"(.*)"/;
	}

	if( !defined $wustl_key ) {
		my $lookup = $ssh_conn->capture("python2.6 /home/meru/meruusertrack/ctrlsearch.py -m $mac -t \'$ctrlsearch_time\' -i 60");
                $wustl_key = $1 if $lookup =~ /wustl key: (\S+)/;
	}

	if( !defined $wustl_key ) {
		my $lookup = $ssh_conn->capture("python2.6 /home/meru/meruusertrack/ctrlsearch.py -m $mac -t \'$ctrlsearch_time\' -i 60");
                $wustl_key = $1 if $lookup =~ /wustl key: (\S+)/;
	}

	abort("Couldn't find WUSTL key.") if !defined $wustl_key;

	return $wustl_key;
}

sub fetch_user_profile($) {
	my $wustl_key = shift;

	# parse the XML data from the user profile lookup
	my $xml = new XML::Simple;
	my $lookup = `wget --no-check-certificate -q -O - \"$key_lookup=$wustl_key\"`;
	my $profile = $xml->XMLin($lookup);

	# determine whether or not the lookup was successful
	return undef if $profile->{'Success'} eq 'false';

	my @fields = (
		$profile->{'Name'}->{'UnifiedName'},
		$wustl_key,
		$profile->{'PrimaryUnit'},
		$profile->{'PrimaryRole'},
		$profile->{'UniversityEmail'},
	);
	return join "  |  ", @fields;
}

# determine which arguments are IP / timestamp
#
sub parse_args {

	( my $ip ) = grep /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/, @_;

	# go through the cmd line arguments to see if any can be parsed into a time
	my $ts = undef;
	foreach( @ARGV ) {
		my $parse_try = str2time($_);
		if( defined $parse_try ) {
			$ts = $parse_try;
		}
	}

	# make sure timestamp and IP are both defined
	unless( defined $ts && defined $ip ) {
		die "Invalid timestamp or IP.";
	}

	return ($ts, $ip);
}

sub usersearch {
	$debug = 1 if grep { $_ eq '-debug' } @ARGV;

	my ( $ts, $ip ) = parse_args(@_);

	print "-"x78 . "\n";
	printf "User lookup for:\t%s  |  %s\n", DateTime->from_epoch(epoch => $ts) . " GMT", $ip;
	print "-"x78 . "\n";

	my $ssh_conn = Net::OpenSSH->new('nsiow@syslog.nts.wustl.edu');
	 $ssh_conn->error and die "Can't ssh to syslog: " . $ssh_conn->error;

	# using timestamp, external ip -> find internal ip
	my $firewall_lines = fetch_firewall_log($ssh_conn, $ts, $ip);
	my $internal_ip = find_internal_ip($firewall_lines, $ts, $ip);

	print "\tinternal ip: $internal_ip\n";

	# using timestamp, internal_ip -> mac address
	my $infoblox_lines = fetch_infoblox_log($ssh_conn, $ts, $internal_ip);
	my $mac_addr = find_mac_addr($infoblox_lines, $ts, $internal_ip);

	print "\tmac address: $mac_addr\n";

	# using timestamp, mac_address -> wustl_key
	my $wustl_key = fetch_wustl_key($ssh_conn, $ts, $mac_addr);

	# using wustl key, get profile
	my $profile = fetch_user_profile($wustl_key);

	print "\tUSER >$profile<\n\n";
}


eval {
	usersearch(@ARGV);
} or do {
	abort('UNKNOWN ERROR');
}

