#!/usr/bin/perl

use v5.10;

use warnings;
use strict;
use autodie;

use Test::More;
use Crypt::Rijndael;
use File::Slurp qw(read_file write_file);
require_ok './cypher.pl';

my $key = "qwerty~~~~~~~~~~";
my $cypher = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC() );

my $text = "abcdefg";

encrypt_decrypt("", "empty");
encrypt_decrypt("1", "one_symbol");
encrypt_decrypt($text, "simple_text");
encrypt_decrypt($text x 1e6, "large_text");
encrypt_decrypt("\0\1\2\3\4\5\6", "simple_bin_data");
encrypt_decrypt('\0' . ("\0\1\2\3\4\5\6" x 1e6), "large_bin_data");

encrypt_decrypt_file("", "empty_file");
encrypt_decrypt_file("1", "one_symbol_file");
encrypt_decrypt_file($text, "simple_text_file");
encrypt_decrypt_file($text x 1e6, "large_text_file");
encrypt_decrypt_file("\0\1\2\3\4\5\6", "simple_bin_file");
encrypt_decrypt_file('\0' . ("\0\1\2\3\4\5\6" x 1e6), "large_bin_file");

done_testing();
exit(0);

sub encrypt_decrypt {
    my $data = shift;
    my $test_name = shift || "encypt_decrypt";

    my $encrypted = encrypt($cypher, $data);
    isnt($encrypted, $data);

    my $decrypted = decrypt($cypher, $encrypted);

    is($decrypted, $data, $test_name);
}

sub encrypt_decrypt_file {
    my $data = shift;
    my $test_name = shift || "encypt_file-decrypt_file";

    my $fname = "/tmp/cypher_test";
    write_file($fname, {binmode => ':raw'}, $data)
    or diag("Can't write $fname: $!")
    and exit(0);
    encrypt_file($cypher, $fname, $fname."_encrypted");
    
    my $encrypted = read_file($fname."_encrypted")
    or diag("Can't read $fname\_encrypted: $!");
    isnt($encrypted, $data);

    decrypt_file($cypher, $fname."_encrypted", $fname."_decrypted");
    
    my $decrypted = read_file($fname."_decrypted");
    # special treatment for an empty file
    if (!defined $decrypted) {
        diag("Can't read $fname\_decrypted: $!");
        exit(1);
    }

    is($decrypted, $data, $test_name);
}

