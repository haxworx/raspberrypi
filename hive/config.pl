#! /usr/bin/perl

use strict;
use warnings;

use Digest::MD5 qw/md5_hex/;
use CGI qw/:standard/;
use CGI::Cookie;
use DBI;

our $SECRET = "JesusIsLord";
my @salt = ( '.', '/', 0 .. 9, 'A' .. 'Z', 'a' .. 'z' );


sub create_cookie {
	my ($username, $password) = @_;

	my $secret = "$username:$SECRET";

	my $cookie_value = md5_hex($secret);

	my $time = time();

	my $expires = $time + 60 * 60;

	my $cgi = CGI->new();

	my $cookie = $cgi->cookie( -name => 'auth',
				  -value => $cookie_value);
	my $last_cookie = $cgi->cookie( -name => 'username',
					-value => $username);

	print "Set-Cookie: $cookie\n";
	print "Set-Cookie: $last_cookie\n";
}

sub check_cookie {
	my ($cookie, $username) = @_;

	my $secret = "$username:$SECRET";

	$secret = md5_hex($secret);

	if ($cookie eq $secret) {
		return 1;
	} else {
		return 0;
	}
}

sub dbh_connect {
        my $dsn = "DBI:mysql:database=hive:host=localhost";
        my $dbh = DBI->connect($dsn, 'hive', 'hive') || browser_message("DBH ERROR");

        return $dbh;
}
