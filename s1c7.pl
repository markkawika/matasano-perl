#!/usr/bin/perl

use strict;
use warnings;
use Carp;
use Crypt::Rijndael;

use MarksStuff qw( base64_to_int_array decrypt_aes_128_ecb
                   int_array_to_string string_to_int_array
                 );

my $filename = '7.txt';
open my $fh, q{<}, $filename
  or croak "Cannot open $filename";
my @lines = <$fh>;
close $fh;
chomp(@lines);

my $base64_ctext = join(q(), @lines);
my @ctext = base64_to_int_array($base64_ctext);
my $key = 'YELLOW SUBMARINE';
my @key = string_to_int_array($key);

my @plaintext = decrypt_aes_128_ecb(\@key, \@ctext);

print int_array_to_string(@plaintext);
