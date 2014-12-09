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

my %freq;
for my $i (0 .. 255) {
  $freq{$i} = 0;
}
for my $i (ord('a') .. ord('z'), ord('A') .. ord('Z'), ord('0') .. ord('9'), ord(q{ })) {
  $freq{$i} = 1;
}

my $fill_size = $block_size - 1;
my @fill = (ord('A')) x $fill_size;
our $OUTPUT_AUTOFLUSH = 1;
for my $decoder_index (0 .. ($hidden_message_length - 1)) {
  # This encrypts using a short "fill" value, to determine the actual
  # encrypted text of the hidden message.
  my @ctext = s2c12_encrypt([ @fill[0 .. ($fill_size - 1)] ]);
  my $target_block = int($decoder_index / $block_size);
  my $block_start = $target_block * $block_size;
  my $block_end = $block_start + $block_size - 1;
  my $ctext_str = int_array_to_string(@ctext[$block_start .. $block_end]);
  my $decoded_character = undef;
  # The following loop tests all possible values between 0 and 255, preferring
  # what it's seen before (pre-seeded with alphanumerics). Once it finds a
  # match, the loop exits and $decoded_character contains the result.
  for my $test_char (reverse sort { $freq{$a} <=> $freq{$b} } (0 .. 255)) {
    my @test_ctext = s2c12_encrypt([ @fill, $test_char ]);
    my $test_str = int_array_to_string(@test_ctext[0 .. ($block_size - 1)]);
    if ($test_str eq $ctext_str) {
      $freq{$test_char}++;
      $decoded_character = $test_char;
      last;
    }
  }
  if (! defined $decoded_character) {
    croak 'Unable to decode a character';
  }
  print chr $decoded_character;
  $fill_size = $fill_size ? $fill_size - 1 : $block_size - 1;
  shift @fill;
  push @fill, $decoded_character;
}
