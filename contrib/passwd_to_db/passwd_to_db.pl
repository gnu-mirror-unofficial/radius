#! /usr/local/bin/perl -w
# Copyright (C) 2004,2007 Gerald Coon
#  
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#  
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#  
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

use DBI;

# Goal is to read in a master.passwd file on a FreeBSD system and put all of the 
# information into a mysql database (that is already created).
# remove the accounts manually from the master.passwd file that you don't want in the DB. 
#
# created by/on:
# Gerald Coon gcoon@inch.com 12/2003

# Global Variables
$passwdfile = "/PATH/TO/MASTERPASSWD";
# On FreeBSD daemon and system accounts are typically below UID 1000. Users start at 1000.
$UIDmin = "1000";

# DB Variables
# couldn't get quotes and the variables for this to work so it's manual for now.
$DBDb = "passwd";
$DBHost = "localhost";
$DBPort = "3306";
$DBDatabase = "DBI:mysql:$DBDb:$DBHost:$DBPort";
$DBTable = "users";
$DBUser = "MYSQL Username";
$DBPass = "MYSQL Password";

## Main Program
&OpenDatabase &&
&Passwordfile &&
# Always close what you open.
&CloseDatabase;

sub OpenDatabase {

	$dbh = DBI->connect($DBDatabase,$DBUser,$DBPass) ||
		die "Could not connect to $DBHost\n";

} # End sub OpenDatabase;

sub Passwordfile {

	open (MASTER_PASSWDFILE, "$passwdfile");
	while (<MASTER_PASSWDFILE>) {

		next if /^#/;      # discard comment lines
		# split our data from the master.passwd file we are working with.
		($username, $cryptpass, $uid, $gid, $trash, $trash, $trash, $gecos, $homedir, $shell) = split(/:/,$_);
		# All usernames will be lowercase in the database. 
		# Comment this out if this does not apply to you.
		$username =~ tr/A-Z/a-z/;
		# single and double quotes piss mysql off when I'm inserting so we escape them here.
                $gecos =~ s/(['"])/\\\1/g;
		# Remove \n from shell
		chop $shell;

		if ($uid >= $UIDmin) {
			# Run the mysql insert with the information we have from this run.
			&Update;
		} # End if uid greater than UIDmin.

	} # End while MASTER_PASSWDFILE

	# Always close what you open.
	close(MASTER_PASSWDFILE);

} # End Passwordfile;

sub Update {
		$sql = "INSERT INTO $DBTable VALUES ('$username','$cryptpass','$uid','$gid','$gecos','$homedir','$shell')";
		$sth = $dbh->prepare($sql);
		$sth->execute || 
			die "Could not execute SQL statement ... New SQL server syntax??";
		$sth->finish;

}; # End sub Update;

sub CloseDatabase {

	$dbh->disconnect || die "Could not clost the database connection to $DBHost\n";

} # End sub CloseDatabase;
