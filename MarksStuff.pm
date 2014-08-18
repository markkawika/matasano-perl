#!/usr/bin/perl

package MarksStuff;

use strict;
use warnings;
use Carp;
use Exporter;
use Crypt::Rijndael;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

$VERSION     = v1.00;
@ISA         = qw(Exporter);
@EXPORT      = ();
@EXPORT_OK   = qw( hex_string_to_int_array
                   string_to_int_array
                   int_array_to_base64
                   int_array_to_string
                   english_score
                   my_xor
                   find_best_xor
                   hamming_distance
                   base64_to_int_array
                   find_best_key_size
                   find_best_key_sizes
                   rkey_xor
                   break_rkey_xor
                   pkcs_7_pad_block
                   decrypt_aes_128_ecb
                   encrypt_aes_128_cbc
                   decrypt_aes_128_cbc
                   encrypt_aes_128_random_mode
                 );

%EXPORT_TAGS = ( DEFAULT => [qw(&hex_string_to_int_array &my_xor)],
                 Both    => [qw(&hex_string_to_int_array &my_xor)]
               );

my $MKS = 40; # Maximum Key Size

sub hex_string_to_int_array {
  my ($str) = @_;
  my @retval;
  while (length($str) > 0) {
    $str =~ s/^([\da-f]{2})//i;
    my $hex_byte = $1;
    push @retval, hex($hex_byte);
  }

  return @retval;
}

# Input: A string
# Output: An array of 8-bit integers
sub string_to_int_array {
  my ($input) = @_;

  return map(ord, split(q(), $input));
}

# Input: A list of 8-bit integers
# Output: The same data, as a single string
sub int_array_to_string {
  my @input = @_;

  return join(q(), map(chr, @input));
}

my @base64_table = qw( A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
                       a b c d e f g h i j k l m n o p q r s t u v w x y z
                       0 1 2 3 4 5 6 7 8 9 + / );

my %base64_values;
{
  my $base64_index = 0;
  for my $base64_digit (@base64_table) {
    $base64_values{$base64_digit} = $base64_index++;
  }
}

sub int_array_to_base64 {
  my @arr = @_;

  my $retstr = q();

  while (@arr > 0) {
    if (@arr >= 3) {
      my $v1 = shift @arr;
      my $v2 = shift @arr;
      my $v3 = shift @arr;
      $retstr .= $base64_table[$v1 >> 2];
      $retstr .= $base64_table[(($v1 & 0x3) << 4) + (($v2 & 0xf0) >> 4)];
      $retstr .= $base64_table[(($v2 & 0xf) << 2) + (($v3 & 0xc0) >> 6)];
      $retstr .= $base64_table[$v3 & 0x3f];
    }
    elsif (@arr == 2) {
      my $v1 = shift @arr;
      my $v2 = shift @arr;
      $retstr .= $base64_table[$v1 >> 2];
      $retstr .= $base64_table[(($v1 & 0x3) << 4) + (($v2 & 0xf0) >> 4)];
      $retstr .= $base64_table[($v2 & 0xf) << 2];
      $retstr .= '=';
    }
    else { # @arr == 1
      my $v1 = shift @arr;
      $retstr .= $base64_table[$v1 >> 2];
      $retstr .= $base64_table[($v1 & 0x3) << 4];
      $retstr .= '==';
    }
  }

  return $retstr;
}

# Arguments: two equal-length arrays containing 8-bit integer scalars.
# Returns: An array of 8-bit ints containing the first array xor'ed with
#          the 2nd.
sub my_xor {
  my ($aref1, $aref2) = @_;
  my @retval = ();
  my $len1 = scalar @{$aref1};
  my $len2 = scalar @{$aref2};

  if ($len1 != $len2) {
    print {*STDERR} "Arrays must be equal length.\n";
    exit 1;
  }

  for (my $i = 0; $i < $len1; $i++) {
    my $v1 = $aref1->[$i];
    my $v2 = $aref2->[$i];
    my $r = $v1 ^ $v2;
    push @retval, $r;
  }

  return @retval;
}

sub english_score {
  my @input = @_;
  my $input_length = scalar @input;

  my %ideal_distribution = (
    ' ' => 0.16626,
    a => 0.06789,
    b => 0.01240,
    c => 0.02313,
    d => 0.03535,
    e => 0.10807,
    f => 0.01852,
    g => 0.01675,
    h => 0.05066,
    i => 0.05791,
    j => 0.00127,
    k => 0.00642,
    l => 0.03346,
    m => 0.02000,
    n => 0.05610,
    o => 0.06240,
    p => 0.01604,
    q => 0.00079,
    r => 0.04977,
    s => 0.05259,
    t => 0.07528,
    u => 0.02293,
    v => 0.00813,
    w => 0.01962,
    x => 0.00125,
    y => 0.01641,
    z => 0.00062,
  );

  my @hist;
  for my $x (0 .. 255) {
    $hist[$x] = 0;
  }
  my %letters;
  for my $l ('a' .. 'z', ' ') {
    $letters{$l} = 0;
  }

  my $num_letters = 0;
  my $printable_chars = 0;
  my $non_letter_penalty = 1.0;
  for my $x (@input) {
    $hist[$x]++;
    my $c = chr($x);
    if ($c !~ /[\p{XPosixPrint}]/) {
      $non_letter_penalty *= 0.9;
    }
    else {
      $printable_chars++;
    }
    next if ($c !~ /[a-z ]/i);
    $c =~ tr/A-Z/a-z/;
    $letters{$c}++;
    $num_letters++;
  }

  my $letter_score = 1.0;
  if ($num_letters == 0) {
    $letter_score = 0.0;
  }
  else {
    for my $c ('a' .. 'z', ' ') {
      my $freq = ($letters{$c} * 1.0) / $num_letters;
      my $diff_from_mean = abs($freq - $ideal_distribution{$c});
      $letter_score -= ($diff_from_mean * $freq);
    }
  }

  # What % of the array was non-letters?
  my $nonletter_ratio = ($input_length - $num_letters) / (1.0 * $input_length);
  # It should be 0%. If it's more, that's a penalty.
  my $nonprintable_score = 1.0 - $nonletter_ratio;

  # What % of the array was printable?
  my $printable_ratio = $printable_chars / (1.0 * $input_length);
  # It should be 100%. If it's less, that's a penalty.
  my $printable_score = 0.0 + $printable_ratio;

  my $letter_score_weight = 0.25;
  my $printable_score_weight = 0.25;
  my $nonprintable_score_weight = 0.5;

  my $score = ($letter_score_weight       * $letter_score)
            + ($nonprintable_score_weight * $nonprintable_score)
            + ($printable_score_weight    * $printable_score);

  return $score;
}

sub find_best_xor {
  my @input = @_;
  my $input_length = scalar @input;

  my $max_score = undef;
  my $best_xor;
  my $best_message = q();

  # Skip XOR 0 -- that's the encrypted text.
  for (my $xor_val = 1; $xor_val < 128; $xor_val++) {
    my @xor_list = ($xor_val) x $input_length;
    my @test_results = my_xor(\@input, \@xor_list);
    my $ascii_output = q();

    for my $byte (@test_results) {
      $ascii_output .= sprintf '%c', $byte;
    }
    #printf {*STDERR} "key [%d] str [%s]\n", $xor_val, $ascii_output;
    my $score = english_score(@test_results);
    if (defined $score && (! defined $max_score || $score > $max_score)) {
      #printf "New record: Xor [%d] Score [%.04f] Message [%s]\n",
      #       $xor_val, $score, $ascii_output;
      $max_score = $score;
      $best_message = $ascii_output;
      $best_xor = $xor_val;
    }
  }
  
  return ($max_score, $best_xor, $best_message);
}

# Input: two array references containing 8-bit integers
# Output: The hamming distance (the total number of bits that differ) between
#         the two arrays.
sub hamming_distance {
  my @array_ref = @_;

  my $total_distance = 0;
  my @vals1 = @{$array_ref[0]};
  my @vals2 = @{$array_ref[1]};

  if (scalar @vals1 != scalar @vals2) {
    print {*STDERR} "Arrays must be equal length.\n";
    exit 1;
  }

  for (my $i = 0; $i < @vals1; $i++) {
    my $x = $vals1[$i] ^ $vals2[$i];
    while ($x > 0) {
      $total_distance += ($x % 2);
      $x >>= 1;
    }
  }

  return $total_distance;
}

sub base64_to_int_array {
  my ($base64_string) = @_;

  if ((length($base64_string) % 4) != 0) {
    croak 'Invalid length of input data. Is that valid base64?';
  }
  if ($base64_string !~ m{^[A-Za-z0-9+/=]*$}) {
    croak 'Invalid base64 string';
  }
  my $i = 0;
  my $j = 0;
  my @retval = ();
  while ($i < length($base64_string)) {
    my @b64 = split(q(), substr($base64_string, $i, 4));

    $retval[$j]  = $base64_values{$b64[0]} << 2;
    $retval[$j] += $base64_values{$b64[1]} >> 4;
    if ($b64[2] ne '=') {
      $retval[$j+1]  = ($base64_values{$b64[1]} & 0x0f) << 4;
      $retval[$j+1] += $base64_values{$b64[2]} >> 2;
      if ($b64[3] ne '=') {
        $retval[$j+2]  = ($base64_values{$b64[2]} & 0x03) << 6;
        $retval[$j+2] += $base64_values{$b64[3]};
      }
    }
    $i += 4;
    $j += 3;
  }

  return @retval;
}

# Input: Two array references: 1) the xor key, 2) the plaintext.
# Output: The encrypted text, formed by repeating-key XOR, as an int array
sub rkey_xor {
  my ($key_ref, $plaintext_ref) = @_;

  my $keylen = scalar @{$key_ref};
  my @crypttext = ();
  my $key_index = 0;

  for my $x (@{$plaintext_ref}) {
    push @crypttext, ($x ^ $key_ref->[$key_index]);
    $key_index = ($key_index + 1) % $keylen;
  }

  return @crypttext;
}

sub find_best_key_sizes {
  my @ctext = @_;
  my %keysizes;
  if (scalar @ctext < 8) {
    croak 'Data must be >= 8 bytes long to find key size.';
  }

  for (my $keysize_guess = 2;
       ($keysize_guess <= $MKS) && (($keysize_guess * 4) <= (scalar @ctext));
       $keysize_guess++) {
    my @block1 = @ctext[ 0                   .. ($keysize_guess     - 1)];
    my @block2 = @ctext[ $keysize_guess      .. ($keysize_guess * 2 - 1)];
    my @block3 = @ctext[($keysize_guess * 2) .. ($keysize_guess * 3 - 1)];
    my @block4 = @ctext[($keysize_guess * 3) .. ($keysize_guess * 4 - 1)];
    my $block_distance = hamming_distance(\@block1, \@block2);
    $block_distance   += hamming_distance(\@block1, \@block3);
    $block_distance   += hamming_distance(\@block1, \@block4);
    $block_distance   += hamming_distance(\@block2, \@block3);
    $block_distance   += hamming_distance(\@block2, \@block4);
    $block_distance   += hamming_distance(\@block3, \@block4);
    my $average_block_distance = $block_distance / 6.0;
    my $normalized_distance = $average_block_distance / $keysize_guess;
    $keysizes{$keysize_guess} = $normalized_distance;
  }

  return (sort { $keysizes{$a} <=> $keysizes{$b} } keys %keysizes);
}

# Input: An array containing 8-bit ints, presumably encrypted with rkey_xor.
# Output: 1: A reference to an array containing the repeating key
#         2: A reference to an array containing the decrypted text
sub break_rkey_xor {
  my @ctext = @_;
  my $best_keysize = (find_best_key_sizes(@ctext))[0];

  my @ctext_blocks = ();
  my @ctext_original = @ctext;
  while (@ctext > 0) {
    push @ctext_blocks, [ splice(@ctext, 0, $best_keysize) ];
  }

  my @transposed_blocks;
  for (my $i = 0; $i < $best_keysize; $i++) {
    my @new_block = ();
    for (my $j = 0; $j < scalar @ctext_blocks; $j++) {
      next if ! defined($ctext_blocks[$j]->[$i]);
      push @new_block, $ctext_blocks[$j]->[$i];
    }
    push @transposed_blocks, \@new_block;
  }

  my $xor_index = 0;
  my @xor_key = ();
  for my $t_block (@transposed_blocks) {
    my $score;
    (undef, $xor_key[$xor_index], undef) = find_best_xor(@{$t_block});
    $xor_index++;
  }

  my @plaintext = rkey_xor(\@xor_key, \@ctext_original);

  return (\@xor_key, \@plaintext);
}

# Input: 1) block size (int), 2) array of 8-bit integers to pad
#        The array size should be <= the block size.
# Output: An array, padded with PKCS#7 padding.
sub pkcs_7_pad_block {
  my ($block_size, @bytes) = @_;
  my $bytes_size = scalar @bytes;

  if ($block_size < $bytes_size) {
    croak "Unable to shrink a block. You must pass in a block <= block_size.";
  }

  my @return_block = @bytes;
  my $num_bytes = ($block_size - $bytes_size);
  if ($num_bytes > 0xff) {
    croak "Cannot pad more than 255 bytes.";
  }

  push @return_block, ($num_bytes) x $num_bytes;
  return @return_block;
}

# Input: Two array references. 1) the key, 2) the ctext. The arrays are the
#        normal "array of 8-bit integers".
# Output: An array of 8-bit integers containing the decrypted plaintext.
sub decrypt_aes_128_ecb {
  my ($key_ref, $ctext_ref) = @_;
  my $key = int_array_to_string(@{$key_ref});
  my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_ECB());

  my $ctext = int_array_to_string(@{$ctext_ref});
  if (length($cipher) % length($key) != 0) {
    croak 'Cipher/Plain text length must be an even multiple of key length.';
  }
  my $plaintext = $cipher->decrypt($ctext);

  return string_to_int_array($plaintext);
}

# Input: Two array references: 1) the key, 2) the ptext. The arrays are the
#        normal "array of 8-bit integers".
# Output: An array of 8-bit integers containing the decrypted plaintext.
sub encrypt_aes_128_ecb {
  my ($key_ref, $ptext_ref) = @_;
  return decrypt_aes_128_ecb($key_ref, $ptext_ref);
}

# Input: three array references. 1) the key, 2) the initialization vector,
#        3) the ptext. The arrays are the normal "array of 8-bit integers".
#        Requirements:
#          Length of Key == Length of init vector
#        Specifically, the data can be shorter than the key. Padding is done
#        with PKCS#7.
# Output: the encrypted ciphertext (list of 8-bit integers)
sub encrypt_aes_128_cbc {
  my ($key_ref, $init_vector_ref, $ptext_ref) = @_;

  my $key_length = scalar @{$key_ref};
  my $block_num = 1;
  my @previous_block;
  my @ptext = @{$ptext_ref};
  my @ctext = ();
  printf {*STDERR} "Size of data is now %d\n", scalar @ptext;

  while (my $ptext_length = scalar @ptext) {
    if ($ptext_length < $key_length) {
      @ptext = pkcs_7_pad_block($key_length, @ptext);
    }
    printf {*STDERR} "After padding, size is now %d\n", scalar @ptext;

    # This strips the first $key_length bytes from @ptext, and puts the
    # removed bytes into @ptext_block.
    my @ptext_block = splice @ptext, 0, $key_length;
    printf {*STDERR} "After splicing, size is now %d\n", scalar @ptext;

    my @modified_block;
    if ($block_num == 1) {
      print {*STDERR} "First block\n";
      printf {*STDERR} "Sizes: ptb [%d] iv [%d]\n", scalar @ptext_block,
                       scalar @{$init_vector_ref};
      @modified_block = my_xor(\@ptext_block, $init_vector_ref);
    }
    else {
      print {*STDERR} "Block $block_num\n";
      printf {*STDERR} "Sizes: ptb [%d] pv [%d]\n", scalar @ptext_block,
                       scalar @previous_block;
      @modified_block = my_xor(\@ptext_block, \@previous_block);
    }
    $block_num++;

    @previous_block = ();
    @previous_block = decrypt_aes_128_ecb($key_ref, \@modified_block);
    push @ctext, @previous_block;
  }

  return @ctext;
}

# Input: three array references. 1) the key, 2) the initialization vector,
#        3) the ptext. The arrays are the normal "array of 8-bit integers".
#        Requirements:
#          Length of Key == Length of init vector
#        Specifically, the data can be shorter than the key. Padding is done
#        with PKCS#7.
# Output: the encrypted ciphertext (list of 8-bit integers)
# Note: This just calls encrypt because encryption / decryption are
#       symmetrical.
sub decrypt_aes_128_cbc {
  my ($key_ref, $init_vector_ref, $ctext_ref) = @_;

  my $key_length = scalar @{$key_ref};
  my $first_block = 1;
  my @previous_block;
  my @ctext = @{$ctext_ref};
  my @ptext = ();

  while (my $ctext_length = scalar @ctext) {
    # This strips the first $key_length bytes from @ctext, and puts the
    # removed bytes into @ctext_block.
    my @ctext_block = splice @ctext, 0, $key_length;
    my @previous_ctext = @ctext_block;

    my @modified_block = decrypt_aes_128_ecb($key_ref, \@ctext_block);

    my @ptext_block;
    if ($first_block == 1) {
      $first_block = 0;
      @ptext_block = my_xor(\@modified_block, $init_vector_ref);
    }
    else {
      @ptext_block = my_xor(\@modified_block, \@previous_block);
    }

    @previous_block = @previous_ctext;
    push @ptext, @ptext_block;
  }

  return @ptext;
}

# Input: None
# Output: An array of 16 8-bit integers: a random 16-byte AES key.
#         NB: This is *not* cryptographically secure.
sub generate_random_aes_key {
  my @aes_key = ();
  for (0 .. 15) {
    push @aes_key, int(rand(256));
  }

  return @aes_key;
}

# Input: An reference to an array of 8-bit integers -- the plaintext
# Output: The input, encrypted with a random AES key, with a 50% chance of
#         using CBC mode, and a 50% chance of using EBC mode. In addition, the
#         plaintext will have 5-10 bytes (the amount will be random) appended
#         to both the beginning and the end of the plaintext.
sub encrypt_aes_128_random_mode {
  my ($ptext_ref) = @_;
  my @key = generate_random_aes_key();
  my @ptext = ();
  my @prefix = ();
  my @suffix = ();
  my $prefix_length = int(rand(6)) + 5;
  my $suffix_length = int(rand(6)) + 5;
  for (1 .. $prefix_length) {
    push @prefix, int(rand(256));
  }
  for (1 .. $suffix_length) {
    push @suffix, int(rand(256));
  }
  push @ptext, @prefix, @{$ptext_ref}, @suffix;
  if (int(rand(2)) == 0) {
    print "CHEATING: I chose ECB mode.\n";
    return encrypt_aes_128_ecb(\@key, \@ptext);
  }
  else {
    print "CHEATING: I chose CBC mode.\n";
    my @init_vector = generate_random_aes_key();
    return encrypt_aes_128_cbc(\@key, \@init_vector, \@ptext);
  }
}

1;
