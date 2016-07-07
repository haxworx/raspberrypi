#!/usr/bin/perl

use strict;
use warnings;

our $SLASH = '/';

package Content;

use Template;
use CGI qw/:standard/;
use Digest::MD5 qw/md5_hex/;
use CGI::Cookie;
use DBI;
use Cwd;

our $DATABASE_NAME = "hive";
our $DATABASE_USER = "hive";
our $DATABASE_PASS = "hive";

my $nwid = undef;
my $nwkey = undef;
my $proxy_enabled = undef;
my $tor_enabled = undef;
my $wap_config_template = "templates/hostapd.conf";

sub new {
	my ($class) = shift;
	my $self = {
		dbh => dbh_connect(),
		cgi => CGI->new(),
		sql_data => undef,
		message => undef,
		template_name => "default",
		fields => {
			username => undef,
			password => undef,
			action => undef, 
			page => undef,
			proxy_mode => undef,
			tor_mode => undef,
			nwid => undef,
			nwkey => undef,
		},
		credentials => {
			authenticated => 0,
			session_id => 0,
		},
	};

	return bless $self, $class;
}

sub execute_as_root {
	my ($self, $args) = @_;

	my $cwd = getcwd();	

	my $exe_suid = "dosuid";

	my $exe_path = "$cwd$SLASH$exe_suid";
	if ( ! -e $exe_path) {
		print "Cannot execute_as_root: missing exe!\n";
	}
	
	my $command_string = "$exe_path $args";

	system($command_string);
}

sub wap_settings_update {
	my ($self) = @_;

	if ($self->fields->{nwid} eq "" || $self->fields->{nwkey} eq "") {
		$self->{message} = "Empty WAP settings!";
		return;
	}

	my $newid = $self->fields->{nwid};
	my $newkey = $self->fields->{nwkey};

	if (length($self->fields->{nwkey}) < 8) {
		$self->{message} = "Wireless passphrase must be greater than 8 characters in length";
		return;
	}	

	my $SQL = "DELETE FROM wifi";
	my $sth = $self->dbh->prepare($SQL);
	$sth->execute();

	$SQL = "INSERT INTO wifi (nwid, nwkey) VALUES (?, ?)";
	$sth = $self->dbh->prepare($SQL);
	$sth->execute($newid, $newkey);

	my $template = Template->new();

	my $vars = {
		NWID => $newid,
		NWKEY => $newkey,
	};	

	my $output = "";

	$template->process($wap_config_template, $vars, \$output);

	my $tempfile = "/var/www/html/tmp/hostapd.conf";
	open(FH, ">$tempfile") || die "open!";

	print FH $output;
	close FH;

	$self->execute_as_root("cp $tempfile /etc/hostapd/hostapd.conf");
	$self->{message} = "Rebooting with new settings!";

	my $pid = fork();
	if ($pid == 0) { # child!
		sleep(5);
		$self->execute_as_root("reboot -h now");
		exit(0);
	}

	return 0;
}

sub wap_state_get {
	my ($self) = @_;

	my $SQL = "SELECT * FROM wifi";
	my $sth = $self->dbh->prepare($SQL);
	$sth->execute();

       	my $row = $sth->fetchrow_hashref();

	$nwkey = $row->{nwkey};
	$nwid =  $row->{nwid};

	return 0;
}

sub proxy_settings_update {
	my ($self) = @_;
	my $mode = 0;

	if ($self->fields->{action} eq "proxy") {
		if (defined $self->fields->{proxy_mode}) {
			$mode = $self->fields->{proxy_mode};
			if ($mode == 1) {
				system("touch /var/www/html/proxy");
				$self->{message} = "Proxy Enabled!";		
				$self->execute_as_root("killall -9 squid");
				$self->execute_as_root("/usr/sbin/squid");
			} else {
				unlink("/var/www/html/proxy");
				$self->{message} = "Proxy Disabled!";
				$self->execute_as_root("killall -9 squid");
			}
			$self->execute_as_root("/etc/rc.local 2>&1 > /dev/null &");	
			my $c = $self->cgi->new();
			print $c->redirect( -location => "/");
			exit(0);
		}
	}
}

sub proxy_state_get {
	my ($self) = @_;
	
	if ( -e "/var/www/html/proxy" ) {
		$proxy_enabled = 1;	
	} else {
		$proxy_enabled = 0;
	}
}

sub tor_settings_update {
	my ($self) = @_;
	my $mode = 0;
	use POSIX ":sys_wait_h";
	
	if ($self->fields->{action} eq "tor") {
		if (defined $self->fields->{tor_mode}) {
			$mode = $self->fields->{tor_mode};
			if ($mode == 1) {
				$self->execute_as_root("cp /var/www/html/templates/squid.conf.tor_enabled /etc/squid/squid.conf");
				system("touch /var/www/html/tor");
			} else {
				$self->execute_as_root("cp /var/www/html/templates/squid.conf.tor_disabled /etc/squid/squid.conf");
				unlink("/var/www/html/tor");
			}

		}

		$self->execute_as_root("killall -9 squid");
		$self->execute_as_root("/usr/sbin/squid");

		my $c = $self->cgi->new();
		print $c->redirect( -location => "/");
		exit(0);
	}
}

sub tor_state_get {
	my ($self) = @_;
	if ( -e "/var/www/html/tor" ) {
		$tor_enabled = 1;
	} else {
		$tor_enabled = 0;
	}
}

sub template {
	my ($self, $page) = @_;

	$self->{template_name} = $page;
}

sub credentials {
	my ($self) = @_;
	return $self->{credentials};
}
sub fields {
	my ($self) = @_;
	return $self->{fields};
}

sub cgi {
	my ($self) = @_;
	return $self->{cgi};
}

sub dbh {
	my ($self) = @_;
	return $self->{dbh};
}

sub dbh_connect {
	my ($self) = shift;
        my $dsn = "DBI:mysql:database=$DATABASE_NAME:host=localhost";
        my $dbh = DBI->connect($dsn, $DATABASE_USER, $DATABASE_PASS) or die "DBH ERROR";

        return $dbh;
}

sub fail {
	my ($self, $mesg) = @_;
	print "Content-type: text/plain\r\n\r\n";
	print "Error: $mesg\r\n";
	exit(1);
}

sub fields_get {
	my ($self) = shift;
	if (! defined $self->fields) { return 0; }
	foreach (%{$self->fields}) {
		if (! defined $_ ) { next; }
		$self->fields->{$_} = $self->cgi->param($_); 
	}	
	return 1;
}

sub sql_update {
	my ($self) = shift;
	my $SQL = "SELECT * FROM users";

	my $sth = $self->dbh->prepare($SQL);
	$sth->execute();	

	my @rows = ();

	while (my $row = $sth->fetchrow_hashref()) {
		push @rows, $row;
	}

	$self->{'sql_data'} = \@rows;

	return \@rows;
}

sub output {
	my ($self, $type) = @_;
	use Template;

	my $template = Template->new();

	my $template_path = "templates" . $SLASH . $self->{template_name};
	if (! -e $template_path) {
		$self->fail("process template path! $template_path");
	}

	my $vars = {
		SQL_DATA => $self->{'sql_data'},
		MESSAGE => $self->{'message'},
		PROXY_STATE => $proxy_enabled,
		TOR_STATE => $tor_enabled,
		NWID => $nwid,
		NWKEY => $nwkey,
	};

	print "Content-type: $type\r\n\r\n";
	$template->process($template_path, $vars) or
		die "template process!";

	$self->dbh->disconnect();
}


our $SECRET = "JesusIsLord";

sub create_cookie {
        my ($self, $username, $password) = @_;

        my $secret = "$username:$SECRET:$password";

        my $cookie_value = md5_hex($secret);

        my $time = time();

        my $expires = $time + 60 * 60;

        my $cookie = $self->cgi->cookie( -name  => 'auth',
					 -value => $cookie_value);

        my $last_cookie = $self->cgi->cookie( -name  => 'username',
					      -value => $username);

        print "Set-Cookie: $cookie\n";
        print "Set-Cookie: $last_cookie\n";
}

sub check_cookie {
        my ($self, $cookie, $username) = @_;

	my $SQL = "SELECT * FROM admin WHERE username = ?";
	my $sth = $self->dbh->prepare($SQL);
	$sth->execute($username);
	my $user = $sth->fetchrow_hashref();
	if (! defined $user) { return 0; };
	my $password = $user->{'password'};

        my $secret = "$username:$SECRET:$password";

        $secret = md5_hex($secret);

        if ($cookie eq $secret) {
                return 1;
        } else {
                return 0;
        }
}

sub authenticated {
	my ($self) = shift;
	return $self->credentials->{'authenticated'};
}

sub authenticate {
	my ($self) = shift;

	my $cookie = $self->cgi->cookie("auth");
	my $username = $self->cgi->cookie("username");
	
	if (! defined($cookie)) {
		my $user_guess = $self->fields->{'username'};
		my $pass_guess = $self->fields->{'password'};

		my $SQL = "SELECT * from admin WHERE username = ?";
		my $sth = $self->dbh->prepare($SQL);
		$sth->execute($user_guess);

		my $admin = $sth->fetchrow_hashref();
		if (! defined($admin)) {
			$self->credentials->{'authenticated'} = 0;
			$self->{template_name} = "login_page";
			return;
		}
		if ($user_guess eq $admin->{'username'} && $pass_guess eq $admin->{'password'}) {
			$self->credentials->{'authenticated'} = 1;
			$self->create_cookie($user_guess, $pass_guess);	
		}
	} elsif ($self->check_cookie($cookie, $username)) {
		$self->credentials->{'authenticated'} = 1;
	}

	if (! $self->credentials->{'authenticated'}) {
		$self->{template_name} = "login_page";
	}

	return $self->credentials->{'authenticated'};
}

sub user_exists {
	my ($self) = shift;
	my $SQL = "SELECT * from users WHERE username = ?";
	my $sth = $self->dbh->prepare($SQL);
	$sth->execute($self->fields->{'username'});
	
	return $sth->fetchrow_hashref() || undef;	
} 

sub user_add {
	my ($self) = shift;

	if ($self->fields->{'username'} eq "" || $self->fields->{'password'} eq "") {
		$self->{'message'} = "empty user or pass";
		return;
	}

	if ($self->fields->{'username'} =~ /\s/) {
		$self->{'message'} = "invalid characters in username";
		return;
	}
	if ($self->fields->{'username'} !~ /[A-Za-z0-9]+/) {
		$self->{'message'} = "invalid characters in username";
		return;
	}

	if ($self->user_exists) {
		$self->{'message'} = "username exists!";
		return;
	}

	$self->{'message'} = "username added!";

	my $SQL = "INSERT into users (username, password, active) VALUES (?, ?, 1)";
	my $sth = $self->dbh->prepare($SQL);
	return $sth->execute($self->fields->{'username'}, $self->fields->{'password'});
}

sub admin_password {
	my ($self) = shift;

	if ($self->fields->{'password'} eq "") {
		$self->{'message'} = "missing fields";
		return 0;
	}

	my $SQL = "UPDATE admin SET password = ? WHERE username = ?";
	my $sth = $self->dbh->prepare($SQL);

	$self->{'message'} = "admin password updated";

	return $sth->execute($self->fields->{'password'}, "admin");
}

sub user_del {
	my ($self) = shift;

	if (! defined $self->fields->{'username'}) {
		$self->{'message'} = "no user selected";
		return undef;
	}

	my $SQL = "DELETE FROM users WHERE username = ?";
	my $sth = $self->dbh->prepare($SQL);

	$self->{'message'} = "username deleted!";

	return $sth->execute($self->fields->{'username'});
}


sub logout {
	my ($self) = shift;
        my $cookie = $self->{cgi}->cookie( -name => 'auth',
				   -value => '');

	$self->{'message'} = "you logged out!";

        print "Set-Cookie: $cookie\n";
	print $self->cgi->redirect( -uri => "/");

	return 0;
}

package main;

use Switch 'Perl6';

sub main {
	my $result = 0;

	my $content = Content->new();

        $content->template("default");

	$content->fields_get();

	$content->tor_state_get();
	$content->wap_state_get();

	$content->proxy_state_get();

	$content->authenticate();

	if ($content->authenticated) {

		given($content->fields->{'action'}) {
			when /^add$/ {  
				$result = $content->user_add(); 
			}
			when /^del$/ {  
				$result = $content->user_del(); 
			}
			when /^pwd$/ { 
				$result = $content->admin_password(); 
			}
			when /^proxy$/ {
				$result = $content->proxy_settings_update();
			}
			when /^wifi$/ {
				$result = $content->wap_settings_update();
				$result = $content->wap_state_get();
			}
			when /^tor$/ {
				$result = $content->tor_settings_update();
				$result = $content->tor_state_get();
			}
			when /^exit$/ {
				$result = $content->logout(); 
			}
		}

		$content->sql_update();
	} 

	$content->output("text/html");	

	return $result;
}

exit(main());

