#!/usr/bin/perl

use strict;
use warnings;
use Carp;

use MarksStuff qw( base64_to_int_array decrypt_aes_128_cbc
                   string_to_int_array int_array_to_string
                 );

my $filename = '10.txt';
open my $fh, q{<}, $filename
  or croak "Cannot open $filename";
my @lines = <$fh>;
close $fh;
chomp(@lines);

my $base64_ctext = join(q(), @lines);
my @ctext = base64_to_int_array($base64_ctext);

my @init_vector = (0) x 16;
my @key = string_to_int_array('YELLOW SUBMARINE');
my @plaintext = decrypt_aes_128_cbc(\@key, \@init_vector, \@ctext);
print int_array_to_string(@plaintext);
