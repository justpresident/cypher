#!/usr/bin/perl

use v5.10;

use warnings;
use strict;
use autodie;

use Data::Dumper;
use Switch;
use Carp;
use Crypt::Rijndael;
use Term::ReadLine;
use Getopt::Long;
use Pod::Usage;

my $DEF_CYPHER_VERSION = 2;
my $DEF_STORE_VERSION = 3;
my $STANDBY_TIMEOUT = 300;
my $last_user_active :shared = time();

GetOptions(
	'encrypt|enc|e' => sub {enc_cmd(\&encrypt)},
	'decrypt|dec|d' => sub {enc_cmd(\&decrypt)},
	'help' => sub {pod2usage(-verbose => 2)},
) or pod2usage();

my $term = Term::ReadLine->new('Cypher')
or croak "Term Readline error";

my $filename = shift
or pod2usage();

my $cypher = mk_cypher($term, $filename);

my $data = load_data($cypher, $filename);

while(1) {
	my $line = $term->readline('cypher > ');
	last if !defined $line;

	last if (time() - $last_user_active > $STANDBY_TIMEOUT);
	$last_user_active = time();

	$line = trim($line);
	next unless $line;

	my ($cmd,@args) = split(/\s+/,$line,3);

	switch($cmd) {
		case "search" { search(@args) }
		case "get" { get(@args) }
		case "put" { put(@args) }
		case "del" { del(@args)}
		case "help" {help(@args)}
		else { say "No such command '$cmd'\n" }
	}
}


system('clear');
exit 0;

########## Data Storage functions #########################

sub put {
	my $key = shift;
	my $val = shift;

	unless ($key && $val) {
		say "syntax: put KEY VAL";
		return;
	}

	$data->{$key} = $val;
	say "$key stored";

	store_data($cypher, $data, $filename);
}

sub get {
	my $re = shift;

	unless($re) {
		say "syntax: get REGEXP";
		return;
	}

	my @keys = grep{$_ =~ /^$re$/}(sort keys %$data);

	unless(scalar(@keys)) {
		say "No keys matching '$re' found!";
		return;
	}

	foreach my $key(@keys) {
		say "$key: ".$data->{$key};
	}
}

sub del {
	my $key = shift;

	my $val = $data->{$key};
	if ($data->{$key}) {
		delete $data->{$key};
		say "$key: $val deleted";

		store_data($cypher, $data, $filename);
	} else {
		say "No such key '$key' found";
	}
}

sub search {
	my $re = shift || '';

	my @keys = grep{$_ =~ /$re/}(sort keys %$data);

	say join("\n", @keys);
}

########### Encrypter functions #############################

sub mk_cypher {
	my $term = shift;
	my $filename = shift;

	my $key = read_password($term, $filename);

	my $cypher = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC() );

	return $cypher;
}

sub enc_cmd {
	my $func = shift;

	my $filename = shift @ARGV;

	defined $filename && -f $filename
	or pod2usage(-verbose => 99, -sections=>["SYNOPSIS", "ARGUMENTS"]);

	my $data = read_file($filename);

	my $cypher = mk_cypher($term, $filename);
	$data = &$func($cypher, $data);

	binmode(STDOUT);
	print $data;

	exit(0);
}

sub encrypt {
	my $cypher = shift;
	my $data = shift;

	my $version = pack('n', $DEF_CYPHER_VERSION);

	my $pad = '~' x (16 - (length($data) % 16));
	$data .= $pad;

	return $version . pack('Ca*', length($pad), $cypher->encrypt($data));
}

sub decrypt {
	my $cypher = shift;
	my $data = shift;

	(my $version, $data) = unpack('na*', $data);

	if ($version == $DEF_CYPHER_VERSION) {
		(my $pad_length, $data) = unpack('Ca*', $data);

		$data = $cypher->decrypt($data);
		$data = substr($data, 0, -1*$pad_length);
	}

	return $data;
}


sub read_password {
	my $term = shift;
	my $filename = shift;

	my $term_attribs = $term->Attribs;
	$term_attribs->{redisplay_function} = $term_attribs->{shadow_redisplay};

	my $key = $term->readline("Enter Password for $filename: ");

	$term->remove_history($term->where_history);
	$term_attribs->{redisplay_function} = undef;

	$key .= '~' x (32 - length($key));

	$term_attribs->{completion_function} = \&autocomplete;

	return $key;
}

########### Data I/O functions ##############################

sub deserialize {
	my $str = shift;

	my $result = {};

	(my $store_version, $str) = unpack('na*', $str);

	if ($store_version == $DEF_STORE_VERSION) {
		(my $elements, $str) = unpack('Na*', $str);
		my $elements_read = 0;
		while($str) {
			(my $k, my $v, $str) = unpack('n/a* N/a* a*', $str);
			if (defined $k) {
				$elements_read++;
				$result->{$k} = $v;
			}
		}

		if ($elements != $elements_read) {
			die "File is corrupted";
		}
	} else {
		die "File format is not supported";
	}
	return $result;
}

sub serialize {
	my $data = shift;

	my $result = pack('n', $DEF_STORE_VERSION);
	$result .= pack('N', scalar(keys %$data));
	keys %$data;
	while (my ($k,$v) = each %$data) {
		$result .= pack('n/a* N/a*', $k, $v);
	}

	return $result;
}

sub load_data {
	my $cypher = shift;
	my $filename = shift;

	unless(-f $filename) {
		return {};
	}

	my $data = read_file($filename);

	$data = decrypt($cypher,$data);

	return deserialize($data);
}

sub store_data {
	my $cypher = shift;
	my $data = shift;
	my $filename = shift;

	my $ice = encrypt($cypher,serialize($data));

	write_file($ice,$filename);

	return 1;
}

sub read_file {
	my $filename = shift;

	open(my $file, "<$filename");
	binmode($file);

	my $fsize = -s $filename;
	my $data = '';

	my $bytes_read = sysread($file, $data, $fsize) || 0;
	
	$bytes_read == $fsize
	or croak("Can't load $file: $!");

	close($file);

	return $data;
}

sub write_file {
	my $data = shift;
	my $filename = shift;

	open(my $file, ">$filename");
	binmode($file);

	syswrite($file, $data)
	or croak("Write $file failed: $!");

	close($file);
}

############# Auto completion ###############################

sub autocomplete {	
	my $text = shift;
	my $line = shift;
	my $start = shift;
	my $end = shift;

	$line = trim($line);

	my ($cmd,@args) = split(/\s+/, $line);
	$cmd ||= '';
	push @args, $text if $text eq '';

#	print "ac: $text,$line\t$cmd,'".scalar(@args)."'\n";

	if (@args) {
		if ($cmd =~ /^(search|get|del|put)$/) {
			return undef if @args > 1;
			return $term->completion_matches($text,\&keyword);
		}
	} else {
		my @all_commands = qw(put get search del help);
		return grep { /^\Q$text/ } (sort @all_commands);
	}

	return undef;
}

{
	my @words = ();
	my $i;
	sub keyword {
		my ($text, $state) = @_;

#		return unless $text;
		if($state) {
			$i++;
		} else { # first call
			$i = 0;
			@words = sort keys %$data;
		}
		for (; $i < scalar(@words); $i++) {
			return $words[$i] if $words[$i] =~ /^\Q$text/;
		};
		return undef;
	}
};

sub trim {
	my $s = shift;
	$s =~ s/^\s+|\s+$//g;
	return $s;
}

=pod

=head1 NAME

=over

Cypher - command line cypher tool to work with encrypted key-value storage. Can be used to encrypt and decrypt whole files

=back

=head1 SYNOPSIS

=over

./cypher [-ed] I<filename>

By default goes into Secure Storage Mode - loads encrypted file and provides interface to manipulate it. See L</USER COMMANDS>. If -e or -d options provided, cypher works as encrypter or decrypter accordingly, dumps its result to STDOUT and exits immediately.

=back

=head1 ARGUMENTS

=over

=item -e I<filename>

Read unencrypted I<filename> and dump it encrypted to STDOUT

=back

=over

=item -d I<filename>

Read encrypted I<filename> and dump it decrypted to STDOUT

=back

=head1 USER COMMANDS

Following commands available in Secure Storage Mode:

=over

=item * put KEY VAL

Puts pair KEY:VAL into storage

=back

=over

=item * get REGEXP

Dumps all data for keys matching perl regexp /^REGEXP\$/

=back

=over

=item * search MASK

Searches and shows all keys, containing MASK as substring

=back

=over

=item * del KEY

Deletes key KEY from storage

=back

=head1 STORAGE MODE FEATURES

You can use <TAB> for autocompletion for commands and data keys

=cut
