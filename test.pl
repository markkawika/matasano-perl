#!/usr/bin/perl

use strict;
use warnings;
use MarksStuff qw( hamming_distance );

my @arr1;
my @arr2;

for my $c (split(q(), 'this is a test')) {
  push @arr1, ord $c;
}
for my $c (split(q(), 'wokka wokka!!!')) {
  push @arr2, ord $c;
}
printf "Test hamming distance: %d\n", hamming_distance(\@arr1, \@arr2);
