#!/usr/bin/perl

use 5.010;
use strict;
use warnings;
use Carp;
use English qw( -no_match_vars );

use MarksStuff qw( s2c12_encrypt find_best_key_sizes int_array_to_string );

sub discover_block_size {
  my @ptext = (ord('A')) x 1024;
  my @ctext = s2c12_encrypt(\@ptext);
  for (my $block_size = 4; $block_size < 512; $block_size++) {
    my @prev_block = @ctext[0 .. ($block_size - 1)];
    my @curr_block;
    my $matches = 0;
    for (my $i = 1; (($i * $block_size) + $block_size) < @ctext; $i++) {
      my $index = $i * $block_size;
      @curr_block = @ctext[$index .. ($index + $block_size - 1)];
      if (@curr_block ~~ @prev_block) {
        $matches++;
      }
      else {
        $matches = 0;
      }
      # Must have four blocks in a row that match to signal success.
      if ($matches == 4) {
        return $block_size;
      }
      @prev_block = @curr_block;
    }
  }
}

my $block_size = discover_block_size();

my %dictionary = ();

my @hidden_message = s2c12_encrypt([]);
my $max_length = scalar @hidden_message;
my $hidden_message_length = undef;
for my $x (1 .. $block_size*2) {
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

my $num_starting_blocks = int($hidden_message_length / $block_size) + 1;
my $starting_size = ($block_size * $num_starting_blocks) - 1;
# BOI == Block Of Interest
my $BOI = $num_starting_blocks - 1;
my $boi_start = $BOI * $block_size;
my $boi_end = $boi_start + ($block_size - 1);
my @decoder = (ord('a')) x $starting_size;
my $decoded_message = q();
print "Here is the decoded message:\n";
our $OUTPUT_AUTOFLUSH = 1;
for (my $i = 0; $i < $hidden_message_length; $i++) {
  my %dictionary = ();
  for (my $x = 0; $x < 256; $x++) {
    my @ctext = s2c12_encrypt([ @decoder, $x ]);
    my $boi_str = int_array_to_string(@ctext[$boi_start .. $boi_end]);
    $dictionary{$boi_str} = $x;
  }
  my @ctext = s2c12_encrypt([ @decoder[ 0 .. (($starting_size - $i) - 1) ] ]);
  my $boi_str = int_array_to_string(@ctext[$boi_start .. $boi_end]);
  my $decoded_character = $dictionary{$boi_str};
  print chr $decoded_character;
  shift @decoder;
  push @decoder, $decoded_character;
  $decoded_message .= chr($decoded_character);
}

print "\n";
