#!/usr/bin/perl

use v5.10;

use warnings;
use strict;
use autodie;

use Storable qw(freeze thaw);
use Data::Dumper;
use Switch;
use Carp;
use Crypt::Rijndael;
use Term::ReadLine;

my $filename = shift
or usage()
and exit 0;

my $term = Term::ReadLine->new('Cypher')
or croak "Term Readline error";

my $key = read_password($term);

my $cypher = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC() );

my $data = load_data($cypher, $filename);

while(1) {
	my $line = $term->readline('cypher > ');
	last if !defined $line;

	$line = trim($line);
	next unless $line;

	my ($cmd,@args) = split(/\s+/,$line);

	switch($cmd) {
		case "search" { search(@args) }
		case "get" { get(@args) }
		case "put" { put(@args) }
		case "del" { del(@args)}
		case "dump" { dump_all(@args) }
		else { say "No such command '$cmd'\n" }
	}
}

exit 0;


sub dump_all {
	print Dumper($data);	
}

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
	my $key = shift;

	my $val = $data->{$key};
	if ($val) {
		say "$key: $val";
	} else {
		say "No such key '$key' found";
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

	my @keys = grep{$_ =~ /$re/}(keys %$data);

	say join("\n", @keys);
}

sub not_impl {
	say "not implemented\n";
}

sub load_data {
	my $cypher = shift;
	my $filename = shift;

	unless(-f $filename) {
		return {};
	}

	open(my $file, "<$filename");
	binmode($file);

	my $fsize = -s $filename;
	my $data = '';

	my $bytes_read = sysread($file, $data, $fsize) || 0;
	
	$bytes_read == $fsize
	or croak("Can't load $file: $!");

	close($file);

	$data = decrypt($cypher,$data);

	return thaw($data);
}

sub store_data {
	my $cypher = shift;
	my $data = shift;
	my $filename = shift;

	open(my $file, ">$filename");
	binmode($file);

	my $ice = encrypt($cypher,freeze($data));

	syswrite($file, $ice)
	or croak("Write $file failed: $!");

	close($file);

	return 1;
}

sub encrypt {
	my $cypher = shift;
	my $data = shift;

	my $pad = '~' x (16 - (length($data) % 16));
	$data .= $pad;

	return length($pad)."-".$cypher->encrypt($data);
}

sub decrypt {
	my $cypher = shift;
	my $data = shift;

	(my $pad_length,$data) = split(/-/,$data,2);

	$data = $cypher->decrypt($data);
	$data = substr($data, 0, -1*$pad_length);

	return $data;
}

sub usage {
	say "
	USAGE: $0 file_name
	";
}

sub read_password {
	my $term = shift;

	my $term_attribs = $term->Attribs;
	$term_attribs->{redisplay_function} = $term_attribs->{shadow_redisplay};

	my $key = $term->readline("Enter Password for $filename: ");

	$term->remove_history($term->where_history);
	$term_attribs->{redisplay_function} = undef;

	$key .= '~' x (32 - length($key));

	$term_attribs->{completion_function} = \&autocomplete;

	return $key;
}

##############################

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
		if ($cmd =~ /^(search|get|del)$/) {
			return undef if @args > 1;
			return $term->completion_matches($text,\&keyword);
		}
	} else {
			my @all_commands = qw(put get search del dump);
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

