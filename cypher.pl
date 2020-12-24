#!/usr/bin/perl

use v5.10;

use warnings;
use strict;
use autodie;

use POSIX qw(strftime);

use Data::Dumper;
$Data::Dumper::Sortkeys = 1;
use Switch;
use Carp;
use Crypt::Rijndael;
use File::Basename qw(basename);
use File::Slurp qw(read_file write_file);
use Term::ReadLine;
use Getopt::Long;
use Pod::Usage;

my $DEF_CYPHER_VERSION = 2;
my $STORE_VER_3 = 3;
my $STORE_VER_4 = 4;
my $DEF_STORE_VERSION = $STORE_VER_4;

my $ENCRYPTED_FILE_VER_1 = 5;

my $STANDBY_TIMEOUT = 300;
my $last_user_active :shared = time();

my $term;
my $filename;
my $cypher;
my $data;

# This is a weird hack to make this file testable.
# If it is included from the test, it will do nothing.
# I don't want to extract all the logic into modules 
# to avoid the need of installing them into the system.
# This is a simple script that contains all the logic in it.
if (basename($0) eq 'cypher.pl') {
    cypher();
}

sub cypher {
    $term = Term::ReadLine->new('Cypher')
        or croak "Term Readline error";

    GetOptions(
        'encrypt|enc|e' => sub {enc_cmd(\&encrypt_file)},
        'decrypt|dec|d' => sub {enc_cmd(\&decrypt_file)},
        'help' => sub {pod2usage(-verbose => 2)},
    ) or pod2usage();

    $filename = shift(@ARGV)
        or print STDERR "File parameter is not found\n"
        and pod2usage();

    $cypher = mk_cypher($term, $filename);

    $data = load_data($cypher, $filename);

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
            case "get" { get(0, @args) }
            case "history" {get(1, @args)}
            case "put" { put(@args) }
            case "del" { del(@args)}
            case "help" {help(@args)}
            else { say "No such command '$cmd'\n" }
        }
    }

    system('clear');
    exit 0;
}
########## Data Storage functions #########################

sub put {
    my $key = shift;
    my $val = shift;

    unless ($key && $val) {
        say "syntax: put KEY VAL";
        return;
    }

    push @{$data->{$key}}, [$val, int(time)];
    say "$key stored";

    store_data($cypher, $data, $filename);
}

sub get {
    my $get_history = shift || 0;
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

    if ($get_history) {
        if (scalar(keys @keys) > 1) {
            say "more than one elements found: ". join(' ', @keys);
            return;
        }
        my $key = $keys[0];
        for my $val (@{$data->{$key}}) {
            my $val_time = strftime("%Y-%m-%d %H:%M:%S",localtime($val->[1]));
            say "[$val_time]: $val->[0]";
        }
    } else {
        foreach my $key(@keys) {
            say "$key: " . $data->{$key}->[-1]->[0];
        }
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

########### Encryption functions #############################

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

    my $cypher = mk_cypher($term, $filename);

    $data = &$func($cypher, $filename);

    binmode(STDOUT);
    print $data;

    exit(0);
}

sub encrypt_file {
    my $cypher = shift;
    my $filename = shift;
    my $out_filename = shift || "-";

    open(my $file, "<", $filename);
    binmode($file);

    my $outfile;
    if ($out_filename eq "-") {
        $outfile = *STDOUT;
    } else {
        open($outfile, ">", $out_filename);
    }
    binmode($outfile);

    my $version = pack('n', $ENCRYPTED_FILE_VER_1);

    syswrite($outfile, $version);

    my $pad_length = 0;
    while($pad_length == 0) {
        my $data = '';
        my $bytes_read = sysread($file, $data, 4096); # read by 4k blocks
        if (!defined $bytes_read) {
            croak("can't read file $file: $!");
        } elsif (!$bytes_read) {
            last;
        }
        if (($bytes_read % 16) != 0) {
            $pad_length = 16 - ($bytes_read % 16);
        }
        if ($pad_length != 0) {
            my $pad = '~' x $pad_length;
            $data .= $pad;
        }

        $data = $cypher->encrypt($data);

        syswrite($outfile, $data);
    }
    close($file);

    syswrite($outfile, pack("C", $pad_length));

    if ($out_filename eq "-") {
        close($out_filename);
    }
}

sub decrypt_file {
    my $cypher = shift;
    my $filename = shift;
    my $out_filename = shift || "-";

    open(my $file, "<", $filename);
    binmode($file);

    my $outfile;
    if ($out_filename eq "-") {
        $outfile = *STDOUT;
    } else {
        open($outfile, ">", $out_filename);
    }

    binmode($outfile);

    my $version;
    my $bytes_read = sysread($file, $version, 2);
    ($version) = unpack('n', $version);
    if (int($version) == $ENCRYPTED_FILE_VER_1) {
        my $last_block = '';
        $bytes_read = sysread($file, $last_block, 4096);
        while($bytes_read == 4096) {
            syswrite($outfile, $cypher->decrypt($last_block));
            $last_block = '';
            $bytes_read = sysread($file, $last_block, 4096);
        }
        # decrypt last block
        if (($bytes_read - 1) % 16 != 0) {
            croak("Unexpected end of file, bytes_read = $bytes_read");
        }
        my $pad_length = unpack('C', substr($last_block,-1));

        my $last_decrypted = $cypher->decrypt(substr($last_block, 0, -1));
        if ($pad_length > 0) {
            $last_decrypted = substr($last_decrypted, 0, -1*$pad_length);
        }
        syswrite($outfile, $last_decrypted);
    } else {
        croak("Unknown file encryption format");
    }

    if ($out_filename eq "-") {
        close($out_filename);
    }
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

########### Passwords file serialization functions ##############################

sub deserialize {
    my $str = shift;

    my $result = {};

    (my $store_version, $str) = unpack('na*', $str);

    # define closure to get next element
    my $get_next_elem_sub;
    if ($store_version == $STORE_VER_3) {
        $get_next_elem_sub = sub {
            (my $k, my $v, $str) = unpack('n/a* N/a* a*', $str);
            return ($k, $v, 0);
        };
    } elsif($store_version == $STORE_VER_4) {
        $get_next_elem_sub = sub {
            (my $k, my $v, my $t, $str) = unpack('n/a* N/a* N a*', $str);
            return ($k, $v, $t);
        };
    }

    # loop to read all elements
    if ($store_version == $STORE_VER_3 || $store_version == $STORE_VER_4) {
        (my $elements, $str) = unpack('Na*', $str);
        my $elements_read = 0;
        while($str) {
            my ($k, $v, $t) = $get_next_elem_sub->();
            if (defined $k) {
                $elements_read++;
                push @{$result->{$k}}, [$v, $t];
            }
        }

        if ($elements != $elements_read) {
            die "File is corrupted";
        }
    } else {
        die "File format is not supported";
    }

    foreach my $key(keys %$result) {
        $result->{$key} = [sort{$a->[1] <=> $b->[1]}(@{$result->{$key}})];
    }

    return $result;
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

########### Data load functions ##############################

sub load_data {
    my $cypher = shift;
    my $filename = shift;

    unless(-f $filename) {
        return {};
    }

    my $data = read_file($filename, { binmode => ':raw' });

    $data = decrypt($cypher,$data);

    return deserialize($data);
}

sub store_data {
    my $cypher = shift;
    my $data = shift;
    my $filename = shift;

    my $ice = encrypt($cypher,serialize($data));

    write_file($filename, {binmode => ':raw'}, $ice);

    return 1;
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
        if ($cmd =~ /^(search|get|history|del|put)$/) {
            return undef if @args > 1;
            return $term->completion_matches($text,\&keyword);
        }
    } else {
        my @all_commands = qw(put get history search del help);
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

1;

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

=item * history KEY

Dumps history of changes of KEY

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

