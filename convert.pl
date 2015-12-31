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
use Getopt::Long;
use Pod::Usage;

my $DEF_CYPHER_VERSION = 2;
my $STORE_VER_3 = 3;
my $STORE_VER_4 = 4;
my $DEF_STORE_VERSION = $STORE_VER_3;


my $filename = shift
or pod2usage();

my $term = Term::ReadLine->new('Cypher convert')
or croak "Term Readline error";

my $cypher = mk_cypher($term, $filename);

my $data = convert_data(load_data($cypher, $filename));

store_data($cypher, $data, "$filename.new");

print Dumper($data);

sub load_data {
	my $cypher = shift;
	my $filename = shift;

	unless(-f $filename) {
		return {};
	}

	my $data = read_file($filename);

	$data = decrypt($cypher,$data);

	return thaw($data);
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

sub convert_data {
	my $data = shift;

	my $result = {};

	foreach my $key(keys %$data) {
		push @{$result->{$key}}, [$data->{$key}, 0];
	}

	return $result;
}

sub decrypt {
	my $cypher = shift;
	my $data = shift;

	(my $pad_length,$data) = split(/-/,$data,2);

	$data = $cypher->decrypt($data);
	$data = substr($data, 0, -1*$pad_length);

	return $data;
}

sub mk_cypher {
	my $term = shift;
	my $filename = shift;

	my $key = read_password($term, $filename);

	my $cypher = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC() );

	return $cypher;
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
############### STORE ######################
sub store_data {
	my $cypher = shift;
	my $data = shift;
	my $filename = shift;

	my $ice = encrypt($cypher,serialize($data));

	write_file($ice,$filename);

	return 1;
}


sub serialize {
	my $data = shift;

	my $elements_count = 0;
	my $body = '';
	keys %$data;
	while (my ($k,$vals_arr) = each %$data) {
		foreach my $val (@$vals_arr) {
			my ($v,$t) = @$val;
			$t ||= int(time);
			if ($DEF_STORE_VERSION == $STORE_VER_3) {
				$body .= pack('n/a* N/a*', $k, $v);
			} elsif ($DEF_STORE_VERSION == $STORE_VER_4) {
				$body .= pack('n/a* N/a* N', $k, $v, $t);
			}
			$elements_count++;
		}
	}

	my $header = pack('n', $DEF_STORE_VERSION);
	$header .= pack('N', $elements_count);

	return $header.$body;
}

sub encrypt {
	my $cypher = shift;
	my $data = shift;

	my $version = pack('n', $DEF_CYPHER_VERSION);

	my $pad = '~' x (16 - (length($data) % 16));
	$data .= $pad;

	return $version . pack('Ca*', length($pad), $cypher->encrypt($data));
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

=pod

=head1 NAME

=over

Converter from old cypher format to new

=back

=head1 SYNOPSIS

=over

./convert FILE_NAME

Converts provided FILE_NAME from old cypher format to new format and stores result in FILE_NAME.new

=back

=cut
