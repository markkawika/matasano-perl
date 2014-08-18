#!/usr/bin/perl

use strict;
use warnings;

use MarksStuff qw( hex_string_to_int_array my_xor );

my $input1 = '1c0111001f010100061a024b53535009181c';
my $input2 = '686974207468652062756c6c277320657965';
my $expected_str = '746865206b696420646f6e277420706c6179';

my @arr1 = hex_string_to_int_array($input1);
my @arr2 = hex_string_to_int_array($input2);
my @expected = hex_string_to_int_array($expected_str);

my @test_results = my_xor(\@arr1, \@arr2);

my $matched = 1;
for (my $i = 0; $i < @test_results; $i++) {
  if ($test_results[$i] != $expected[$i]) {
    $matched = 0;
    last;
  }
}

if ($matched) {
  print "It succeeded!\n";
}
else {
  print "It did not succeed!\n";
}
