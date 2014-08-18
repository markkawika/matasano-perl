#!/usr/bin/perl

use strict;
use warnings;
use open qw(:std :utf8);

use MarksStuff qw( base64_to_int_array break_rkey_xor
                   int_array_to_string
                 );

open my $fh, q{<}, '6.txt'
  or die 'Cannot open 6.txt';

my @lines = <$fh>;
close $fh;
chomp(@lines);
my $base64_ctext = join(q(), @lines);

my @ctext = base64_to_int_array($base64_ctext);
my ($xor_key_ref, $ptext_ref) = break_rkey_xor(@ctext);

printf {*STDERR} "xor key is [%s]\n", int_array_to_string(@{$xor_key_ref});
print "Plaintext reads:\n";
print int_array_to_string(@{$ptext_ref});
print "\n";
