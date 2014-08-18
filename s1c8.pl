#!/usr/bin/perl

use strict;
use warnings;
use Carp;

use MarksStuff qw( hex_string_to_int_array hamming_distance );

my $filename = '8.txt';
open my $fh, q{<}, $filename
  or croak "Cannot open $filename";
my @lines = <$fh>;
close $fh;
chomp(@lines);

my @ctexts = ();
for my $line (@lines) {
  my @bytes = hex_string_to_int_array($line);
  push @ctexts, \@bytes;
}

my $max_identical_blocks = 0;
my @ecb_block = ();
for my $ctext_ref (@ctexts) {
  my @ctext = @{$ctext_ref};
  my @blocks = ();
  while (@ctext > 0) {
    my @block = splice(@ctext, 0, 16);
    push @blocks, \@block;
  }
  my $num_identical_blocks = 0;
  for (my $i = 0; $i < (scalar @blocks) - 1; $i++) {
    for (my $j = ($i+1); $j < (scalar @blocks); $j++) {
      if (hamming_distance($blocks[$i], $blocks[$j]) == 0) {
        $num_identical_blocks++;
      }
    }
  }
  if ($num_identical_blocks > $max_identical_blocks) {
    $max_identical_blocks = $num_identical_blocks;
    print "Found $max_identical_blocks. This is a new record.\n";
    @ecb_block = @{$ctext_ref};
  }
}
