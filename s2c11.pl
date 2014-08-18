#!/usr/bin/perl

use strict;
use warnings;
use MarksStuff qw( encrypt_aes_128_random_mode hamming_distance );

my @ptext = ();
for (0 .. 47) {
  push @ptext, 0;
}

my @ctext = encrypt_aes_128_random_mode(\@ptext);

my @block1 = @ctext[16 .. 23];
my @block2 = @ctext[24 .. 31];

if (hamming_distance(\@block1, \@block2) == 0) {
  print "This was encrypted using ECB.\n";
}
else {
  print "This was encrypted using CBC.\n";
}
