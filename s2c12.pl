#!/usr/bin/perl

use 5.010;
use strict;
use warnings;
use Carp;
use English qw( -no_match_vars );

use MarksStuff qw( s2c12_encrypt find_best_key_sizes int_array_to_string );

sub discover_block_size {
  my $MAX_BLOCK_SIZE = 512;
  for (my $block_size = 4; $block_size < $MAX_BLOCK_SIZE; $block_size++) {
    my @ctext = s2c12_encrypt([ (ord('A')) x ($block_size * 4) ]);
    my @first_block = @ctext[0 .. ($block_size - 1)];
    my $matches = 0;
    for (my $i = 1; (($i * $block_size) + $block_size) < @ctext; $i++) {
      my $index = $i * $block_size;
      my @curr_block = @ctext[$index .. ($index + $block_size - 1)];
      if (@curr_block ~~ @first_block) {
        $matches++;
      }
      # Must have four blocks in a row that match to signal success.
      if ($matches == 3) {
        return $block_size;
      }
    }
  }
  return -1;
}

my $block_size = discover_block_size();
croak 'Unable to determine block size'
  if ($block_size == -1);

my %dictionary = ();

my @hidden_message = s2c12_encrypt([]);
my $max_length = scalar @hidden_message;
my $hidden_message_length = undef;
# AES blocksize is 16, but keysize can be up to 32. PKCS#7 padding is done off
# of key_size, not block_size, so we'll need to test up to 2*block_size
# iterations.
for my $x (1 .. ($block_size * 2)) {
  my @ctext = s2c12_encrypt([ (ord('a')) x $x ]);
  if (scalar @ctext > $max_length) {
    $hidden_message_length = $max_length - ($x - 1);
    last;
  }
}

if (! defined($hidden_message_length)) {
  # This can only happen if something is wrong
  croak 'How can this be possible? Unable to detect message length';
}

# Integer division is in use -- no FP division.
my $num_starting_blocks;
{
  use integer;
  # if HML is 139, and blocksize is 16, NSB becomes (139 / 16) + 1 == 9
  $num_starting_blocks = ($hidden_message_length / $block_size) + 1;
}
# starting_size becomes 16 * 9 - 1 == 143
my $starting_size = ($block_size * $num_starting_blocks) - 1;
# BOI == Block Of Interest
# BOI becomes 9 - 1 == 8
my $BOI = $num_starting_blocks - 1;
# boi_start becomes 8 * 16 = 128
my $boi_start = $BOI * $block_size;
# boi_end becomes 128 + (16 - 1) == 128 + 15 == 143
my $boi_end = $boi_start + ($block_size - 1);
my @decoder = (ord('a')) x $starting_size;
my $decoded_message = q();
print "Here is the decoded message:\n";
our $OUTPUT_AUTOFLUSH = 1;
# Example of how this works:
# 
# Example block_size of 8, HML of 15. Derived values:
# $hidden_message:      "X, X, X, ..."
# $num_starting_blocks: 2
# $starting_size:      15
# $BOI:                 1
# $boi_start:           8
# $boi_end:             15
# @decoder:
# ( 97 97 97 97 97 97 97 97
#   97 97 97 97 97 97 97 )
# If we just encrypt @decoder, the ptext first becomes:
# ( 97 97 97 97 97 97 97 97
#   97 97 97 97 97 97 97  X
#    X  X  X  X  X  X  X  X
#    X  X  X  X  X  X  X  1 )
# (Note the PKCS#7 padding at the end)
#
# Then, I build a dictionary by appending 0 .. 255 onto the end of @decoder
# and encrypting. This allows me to build a dictionary of the ctext values
# for:
# ( 97 97 97 97 97 97 97 0 )
# ( 97 97 97 97 97 97 97 1 )
# ( 97 97 97 97 97 97 97 2 )
# ...
# ( 97 97 97 97 97 97 97 255 )
# 
# Then, I encrypt @decoder. Then I can compare the encrypted block value of
# ( 97 97 97 97 97 97 97 X )
# to all of my dictionaries to determine the value of X.

my %freq;
for my $i (0 .. 255) {
  $freq{$i} = 0;
}
for my $i (ord('a') .. ord('z'), ord('A') .. ord('Z'), ord(q{ })) {
  $freq{$i} = 1;
}

for (my $i = 0; $i < $hidden_message_length; $i++) {
  my %dictionary = ();
  my @ctext = s2c12_encrypt([ @decoder[ 0 .. (($starting_size - $i) - 1) ] ]);
  my $decoded_character = undef;
  for my $x (reverse sort { $freq{$a} <=> $freq{$b} } (0 .. 255)) {
    my $boi_str = int_array_to_string(@ctext[$boi_start .. $boi_end]);
    my @test_ctext = s2c12_encrypt([ @decoder, $x ]);
    my $test_str = int_array_to_string(@test_ctext[$boi_start .. $boi_end]);
    if ($test_str eq $boi_str) {
      $freq{$x}++;
      $decoded_character = $x;
      last;
    }
  }
  if (! defined $decoded_character) {
    croak 'Unable to decode a character';
  }
  print chr $decoded_character;
  shift @decoder;
  push @decoder, $decoded_character;
  $decoded_message .= chr($decoded_character);
}
