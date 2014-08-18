#!/usr/bin/perl

use strict;
use warnings;

use MarksStuff qw( hex_string_to_int_array my_xor english_score find_best_xor
                 );

my $input_hex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736';
my @input = hex_string_to_int_array($input_hex);

my ($score, $xor, $message) = find_best_xor(@input);

print "Score: $score\n";
printf "0x%02x: [%s]\n", $xor, $message;
