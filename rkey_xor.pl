#!/usr/bin/perl

use strict;
use warnings;
use English qw( -no_match_vars );

# Input: two strings.
# Output: repeating-key XOR, where the first argument is the xor key, and the
# second argument is the plaintext to "encrypt".
sub repeating_key_xor {
  my ($key, @plaintext) = @_;
  printf "Found key: %s\n", $key;

  my $keylen = length($key);
  my $crypttext = q();
  my $key_index = 0;

  for my $line (@plaintext) {
    for my $i (split(q(), $line)) {
      $crypttext .= ($i ^ substr($key, $key_index, 1));
      $key_index = ($key_index + 1) % $keylen;
    }
  }

  return $crypttext;
}

if (@ARGV != 1) {
  print {*STDERR} "Usage:\n";
  print {*STDERR} "cat plaintext_file | $PROGRAM_NAME <key>\n";
  exit 1;
}

my $xor_key = $ARGV[0];
my @lines = <STDIN>;
my $line = repeating_key_xor($xor_key, @lines);

my $x = 0;
for my $c (split(q(), $line)) {
  printf "%02x", ord($c);
  $x += 1;
  if ($x == 36) {
    $x = 0;
    print "\n";
  }
}
print "\n";
