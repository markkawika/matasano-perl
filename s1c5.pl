#!/usr/bin/perl

use strict;
use warnings;

use MarksStuff qw( rkey_xor );

my $plaintext_string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
my $xor_string = 'ICE';
my @input = ();
my @xor_key = ();

for my $char (split(q(), $plaintext_string)) {
  push @input, ord($char);
}
for my $char (split(q(), $xor_string)) {
  push @xor_key, ord($char);
}

my @plaintext = rkey_xor(\@xor_key, \@input);

my $count = 0;
for my $x (@plaintext) {
  printf '%02x', $x;
  $count += 1;
  if ($count == 37) {
    $count = 0;
    print "\n";
  }
}
print "\n";
