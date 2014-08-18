#!/usr/bin/perl

use strict;
use warnings;
use MarksStuff qw( hex_string_to_int_array int_array_to_base64 );

my $expected_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t';
my $input_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d';

my $accum_index = 0;
my $value = 0;

my @input = hex_string_to_int_array($input_string);
my $base64_output = int_array_to_base64(@input);

print "$base64_output\n";
if ($base64_output eq $expected_output) {
  print "It matches!\n";
}
else {
  print "It doesn't match!\n";
}
