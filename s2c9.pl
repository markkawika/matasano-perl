#!/usr/bin/perl

use strict;
use warnings;
use Carp;

use MarksStuff qw( pkcs_7_pad_block int_array_to_string 
                   string_to_int_array
                 );

my $input_string = 'YELLOW SUBMARINE';
my @bytes = string_to_int_array($input_string);

my @padded_block = pkcs_7_pad_block(20, @bytes);
printf "padded block is [%s]\n", int_array_to_string(@padded_block);
