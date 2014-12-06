#!/usr/bin/perl

use strict;
use warnings;
use MarksStuff qw( encrypt_aes_128_random_mode hamming_distance );

my @ptext = map(ord('a'), 0 .. 47);

my @ctext = encrypt_aes_128_random_mode(\@ptext);

my @block1 = @ctext[16 .. 31];
my @block2 = @ctext[32 .. 47];

my $hamming_dist = hamming_distance(\@block1, \@block2);
if ($hamming_dist == 0) {
  print "This was encrypted using ECB.\n";
}
else {
  print "This was encrypted using CBC.\n";
}
