#!/usr/bin/env perl

# Author:  philsmd
# Date:    July 2022
# License: public domain, credits go to philsmd and hashcat

# Version: 0.03

# Last updated:
# July 13 2022

# Note: this tool is heavily based on the public domain tool 7z2hashcat from philsmd
# many functions and file reading/writing ideas are derived directly from 7z2hashcat

use strict;
use warnings;

use Digest::CRC qw (crc32);


#
# Constants
#

my $TOOL_NAME    = "hc_to_7z";
my $TOOL_VERSION = "0.03";

my $SEVEN_ZIP_FILE_NAME     = "a\x00.\x00t\x00x\x00t\x00"; # a.txt
my $SEVEN_ZIP_SIGNATURE_LEN = 32;

my $SEVEN_ZIP_TIME_OFFSET = 11644473600; # offset between unix/win epoch, 1/1/1970 vs 1/1/1601

my $SEVEN_ZIP_OUTPUT_NAME     = "tmp";
my $SEVEN_ZIP_FILE_PERMISSION = 664; # octal/numeric chmod format, 664 = -rw-rw-r--

my $SEVEN_ZIP_MAGIC = "7z\xbc\xaf\x27\x1c";

my $SEVEN_ZIP_END                = "\x00";
my $SEVEN_ZIP_HEADER             = "\x01";
my $SEVEN_ZIP_MAIN_STREAMS_INFO  = "\x04";
my $SEVEN_ZIP_FILES_INFO         = "\x05";
my $SEVEN_ZIP_PACK_INFO          = "\x06";
my $SEVEN_ZIP_UNPACK_INFO        = "\x07";
my $SEVEN_ZIP_SUBSTREAMS_INFO    = "\x08";
my $SEVEN_ZIP_SIZE               = "\x09";
my $SEVEN_ZIP_CRC                = "\x0a";
my $SEVEN_ZIP_FOLDER             = "\x0b";
my $SEVEN_ZIP_UNPACK_SIZE        = "\x0c";
my $SEVEN_ZIP_NAME               = "\x11";
my $SEVEN_ZIP_MODIFICATION_TIME  = "\x14";
my $SEVEN_ZIP_WIN_ATTRIBUTE      = "\x15";
my $SEVEN_ZIP_DUMMY              = "\x19";

my $SEVEN_ZIP_ALL_DEFINED        = "\x01";

my $SEVEN_ZIP_HASH_SIGNATURE     = "\$7z\$";
my $SEVEN_ZIP_MIN_HASH_FIELD_NUM =  12;
my $SEVEN_ZIP_MAX_HASH_FIELD_NUM =  15;
my $SEVEN_ZIP_FILE_EXTENSION     = "7z";
my $SEVEN_ZIP_TRUNCATED          = 128;

# mostly all from: CPP/7zip/Archive/7z/7zHeader.h

my $SEVEN_ZIP_AES     = "\x06\xf1\x07\x01"; # 06f10701
my $SEVEN_ZIP_LZMA1   = "\x03\x01\x01";
my $SEVEN_ZIP_LZMA2   = "\x21";
my $SEVEN_ZIP_PPMD    = "\x03\x04\x01";
my $SEVEN_ZIP_BCJ     = "\x03\x03\x01\x03";
my $SEVEN_ZIP_BCJ2    = "\x03\x03\x01\x1b";
my $SEVEN_ZIP_PPC     = "\x03\x03\x02\x05";
my $SEVEN_ZIP_ALPHA   = "\x03\x03\x03\x01";
my $SEVEN_ZIP_IA64    = "\x03\x03\x04\x01";
my $SEVEN_ZIP_ARM     = "\x03\x03\x05\x01";
my $SEVEN_ZIP_ARMT    = "\x03\x03\x07\x01";
my $SEVEN_ZIP_SPARC   = "\x03\x03\x08\x05";
my $SEVEN_ZIP_BZIP2   = "\x04\x02\x02";
my $SEVEN_ZIP_DEFLATE = "\x04\x01\x08";
my $SEVEN_ZIP_DELTA   = "\x03";
my $SEVEN_ZIP_COPY    = "\x00";

my $SEVEN_ZIP_UNCOMPRESSED       = 0;
my $SEVEN_ZIP_LZMA1_COMPRESSED   = 1;
my $SEVEN_ZIP_LZMA2_COMPRESSED   = 2;
my $SEVEN_ZIP_PPMD_COMPRESSED    = 3;
my $SEVEN_ZIP_BZIP2_COMPRESSED   = 6;
my $SEVEN_ZIP_DEFLATE_COMPRESSED = 7;

my $SEVEN_ZIP_NOT_PREPROCESSED   = 0;
my $SEVEN_ZIP_BCJ_PREPROCESSED   = 1;
my $SEVEN_ZIP_BCJ2_PREPROCESSED  = 2;
my $SEVEN_ZIP_PPC_PREPROCESSED   = 3;
my $SEVEN_ZIP_IA64_PREPROCESSED  = 4;
my $SEVEN_ZIP_ARM_PREPROCESSED   = 5;
my $SEVEN_ZIP_ARMT_PREPROCESSED  = 6;
my $SEVEN_ZIP_SPARC_PREPROCESSED = 7;
                                 # 8 conflicts with SEVEN_ZIP_TRUNCATED (128 == 0x80 == 8 << 4)
my $SEVEN_ZIP_DELTA_PREPROCESSED = 9;

my $SEVEN_ZIP_AES_DEFAULT_ATTRIBUTES = 0x40; # e.g. 0x40 + 0x13 = 0x53, 0x13 => 2^19 rounds

my $SEVEN_ZIP_CODEC_IDS =
[
  # SEVEN_ZIP_ALPHA and SEVEN_ZIP_COPY missing:
  # compressors:
  {
    $SEVEN_ZIP_UNCOMPRESSED       => $SEVEN_ZIP_COPY,
    $SEVEN_ZIP_LZMA1_COMPRESSED   => $SEVEN_ZIP_LZMA1,
    $SEVEN_ZIP_LZMA2_COMPRESSED   => $SEVEN_ZIP_LZMA2,
    $SEVEN_ZIP_PPMD_COMPRESSED    => $SEVEN_ZIP_PPMD,
    $SEVEN_ZIP_BZIP2_COMPRESSED   => $SEVEN_ZIP_BZIP2,
    $SEVEN_ZIP_DEFLATE_COMPRESSED => $SEVEN_ZIP_DEFLATE,
  },
  # (preprocessing) filters:
  {
    $SEVEN_ZIP_NOT_PREPROCESSED   => $SEVEN_ZIP_COPY,
    $SEVEN_ZIP_BCJ_PREPROCESSED   => $SEVEN_ZIP_BCJ,
    $SEVEN_ZIP_BCJ2_PREPROCESSED  => $SEVEN_ZIP_BCJ2,
    $SEVEN_ZIP_PPC_PREPROCESSED   => $SEVEN_ZIP_PPC,
    $SEVEN_ZIP_IA64_PREPROCESSED  => $SEVEN_ZIP_IA64,
    $SEVEN_ZIP_ARM_PREPROCESSED   => $SEVEN_ZIP_ARM,
    $SEVEN_ZIP_ARMT_PREPROCESSED  => $SEVEN_ZIP_ARMT,
    $SEVEN_ZIP_SPARC_PREPROCESSED => $SEVEN_ZIP_SPARC,
    $SEVEN_ZIP_DELTA_PREPROCESSED => $SEVEN_ZIP_DELTA,
  }
];


#
# Helper functions
#

# Notes for add_number ():

# byte swapped (after first byte) !!!
#               output: ->        input:
# len 1:             00 ->             0
#                    7f ->           127
# len 2:           8080 ->           128 (note: 8081 -> 129, 8100 -> 256)
#                  bfff ->         16383
# len 3:         c00040 ->         16384 (note: c10000 -> 65536, c00140 -> 16385)
#                dfffff ->       2097151
# len 4:       e0000020 ->       2097152
#              efffffff ->     268435455
# len 5:     f000000010 ->     268435456
#            f7ffffffff ->   34359738367
# len 6:   f80000000008 ->   34359738368
#          fbffffffffff -> 4398046511103
# len 7: fc000000000004 -> 4398046511104
# ...

# first byte (output) encoding:
# > 0x00 (0b00000000) -> read 0 extra bytes (length: 1), + 0x80 =>
# > 0x80 (0b10000000) -> read 1 extra byte  (length: 2), + 0x40 =>
# > 0xc0 (0b11000000) -> read 2 extra bytes (length: 3), + 0x20 =>
# > 0xe0 (0b11100000) -> read 3 extra bytes (length: 4), + 0x10 =>
# > 0xf0 (0b11110000) -> read 4 extra bytes (length: 5), + 0x08 =>
# > 0xf8 (0b11111000) -> read 5 extra bytes (length: 6), + 0x04 =>
# > 0xfc (0b11111100) -> read 6 extra bytes (length: 7), + 0x02 =>
# > 0xfe (0b11111110) -> read 7 extra bytes (length: 8), + 0x01 =>
# > 0xff (0b11111111) -> read 8 extra bytes (length: 9)

# reverse of 7z2hashcat's read_number ():

sub add_number
{
  my $num = shift;

  my $ret = "";

  if ($num < 0x80)
  {
    $ret = chr ($num);

    return $ret;
  }

  # determine the length needed:

  my $len = 1;

  my $max = 0x7f;

  while ($num > $max) # first time it's true for sure
  {
    if ($len > 8)
    {
      print STDERR "ERROR: Could not encode the very, very large number $num ";
      print STDERR "(> 0x7fffffffffffffff)\n";

      return chr (0);
    }

    $max = ($max << 7) | 0x7f; # 7-bit blocks

    $len++;
  }

  my $first_byte = 0;

  for (my $i = 0; $i < $len - 1; $i++)
  {
    $first_byte |= (0x80 >> $i);
  }

  my $main_bytes = "";

  for (my $i = 0; $i < $len - 1; $i++)
  {
    $main_bytes .= chr ($num & 0xff);

    $num >>= 8;
  }

  $first_byte |= $num; # yeah, we can store some remaining bits here

  $ret = chr ($first_byte) . $main_bytes;

  return $ret;
}

sub seven_zip_header
{
  my $parsed_header = shift;

  my $ret = "";

  $ret .= $SEVEN_ZIP_HEADER;


  #
  # seven_zip_streams_info (from read_seven_zip_streams_info ()):
  #

  $ret .= $SEVEN_ZIP_MAIN_STREAMS_INFO;


  # start of pack info:

  my $streams_info = $parsed_header->{'streams_info'};
  my $pack_info    = $streams_info->{'pack_info'};

  $ret .= $SEVEN_ZIP_PACK_INFO;

  my $pack_pos = $pack_info->{'pack_pos'};

  $ret .= add_number ($pack_pos);

  my $num_pack_streams = $pack_info->{'number_pack_streams'};

  $ret .= add_number ($num_pack_streams);


  $ret .= $SEVEN_ZIP_SIZE; # wait_for_seven_zip_id (), "size id"

  my $pack_size = $pack_info->{'pack_sizes'}[0];

  $ret .= add_number ($pack_size);

  $ret .= $SEVEN_ZIP_END;


  # start of unpack info:

  my $unpack_info = $streams_info->{'unpack_info'};

  $ret .= $SEVEN_ZIP_UNPACK_INFO;
  $ret .= $SEVEN_ZIP_FOLDER;

  my $num_folders = $unpack_info->{'number_folders'};

  $ret .= add_number ($num_folders);

  my $external = 0;

  $ret .= add_number ($external);

  # in read_seven_zip_folders ():

  my $first_folder = $unpack_info->{'folders'}->[0];

  my $num_of_coders = $first_folder->{'number_coders'};

  $ret .= add_number ($num_of_coders); # or use chr ()

  my $sum_input_streams  = 0;
  my $sum_output_streams = 0;

  for (my $i = 0; $i < $num_of_coders; $i++)
  {
    my $main_byte_add = 0x20;

    my $coder = $first_folder->{'coders'}->[$i];

    my $num_input_streams  = $coder->{'number_input_streams'};
    my $num_output_streams = $coder->{'number_output_streams'};

    if (($num_input_streams != 1) || ($num_output_streams != 1))
    {
      $main_byte_add += 0x10;
    }

    my $codec_id = $coder->{'codec_id'};

    my $codec_id_len = length ($codec_id);

    my $main_byte = $codec_id_len + $main_byte_add;

    $ret .= chr ($main_byte); # length + info (0x20 and optional 0x10)
    $ret .= $codec_id;  # then the ID itself

    if (($main_byte & 0x10) != 0)
    {
      $ret .= add_number ($num_input_streams);
      $ret .= add_number ($num_output_streams);
    }

    $sum_input_streams  += $num_input_streams;
    $sum_output_streams += $num_output_streams;

    if (($main_byte & 0x020) != 0)
    {
      my $attributes = $coder->{'attributes'};

      my $property_size = length ($attributes);

      $ret .= add_number ($property_size); # or use chr ()
      $ret .= $attributes;
    }
  }

  if (($sum_input_streams != 1) || ($sum_output_streams != 1))
  {
    my $num_bindpairs = $sum_output_streams - 1;

    for (my $i = 0; $i < $num_bindpairs; $i++)
    {
      my $bindpair = $first_folder->{'bindpairs'}[$i];

      my $index_input  = $bindpair->[0];
      my $index_output = $bindpair->[1];

      $ret .= add_number ($index_input);
      $ret .= add_number ($index_output);
    }

    my $sum_packed_streams = $sum_input_streams - $num_bindpairs;

    if ($sum_packed_streams != 1)
    {
      for (my $i = 0; $i < $sum_packed_streams; $i++)
      {
        my $index = $i; # FIX

        $ret .= add_number ($index);
      }
    }
  }

  my $sum_coders_output_streams = $first_folder->{'sum_output_streams'};


  # done with folder (read_seven_zip_folders ()):

  $ret .= $SEVEN_ZIP_UNPACK_SIZE;

  my $unpack_sizes = $unpack_info->{'unpack_sizes'};

  for (my $i = 0; $i < $sum_coders_output_streams; $i++)
  {
    my $unpack_size = $unpack_sizes->[$i];

    $ret .= add_number ($unpack_size);
  }

  $ret .= $SEVEN_ZIP_END; # or sometimes $SEVEN_ZIP_CRC ?


  # start of substreams info:

  $ret .= $SEVEN_ZIP_SUBSTREAMS_INFO;

  $ret .= $SEVEN_ZIP_CRC;

  my $num_substreams = 1;

  my $index = 1; # $unpack_info->{'coder_unpack_sizes'}[0] +
                 # $unpack_info->{'main_unpack_size_index'}[0];

  my $unpack_size_tmp = $unpack_info->{'unpack_sizes'}[$index];

  my $num_digests = 1; # depends on $num_substreams

  $ret .= $SEVEN_ZIP_ALL_DEFINED; # all CRCs are defined !

  for (my $i = 0; $i < $num_substreams; $i++)
  {
    my $substreams_info = $streams_info->{'substreams_info'};
    my $digests         = $substreams_info->{'digests'};

    $ret .= pack ("L<", $digests->[$i]->{'crc'});
  }

  $ret .= $SEVEN_ZIP_END; # end of loop

  # $len_defined != $len_unpack_sizes : special case

  $ret .= $SEVEN_ZIP_END; # end of substreams info (read_seven_zip_substreams_info ()
                          # and read_seven_zip_streams_info ())


  #
  # seven_zip_files_info (from read_seven_zip_files_info ()):
  #

  $ret .= $SEVEN_ZIP_FILES_INFO;

  # read_seven_zip_files_info ():

  my $files_info = $parsed_header->{'files_info'};
  my $first_file = $files_info->{'files'}->[0]; # we always only have 1 file (index 0)

  my $num_files = $files_info->{'number_files'}; # 1

  $ret .= add_number ($num_files); # or use chr ()


  # loop properties

  my $property_type;
  my $property_size;


  # DUMMY:

  # $property_type = $SEVEN_ZIP_DUMMY;  # really needed ? for alignment and testing (if \x00)?

  # $ret .= $property_type;

  # $property_size = 6;

  # $ret .= add_number ($property_size);

  # $ret .= "\x00" x $property_size;


  # NAME:

  $property_type = $SEVEN_ZIP_NAME;

  $ret .= $property_type;

  my $file_name_utf16 = $first_file->{'name_utf16'};

  $property_size = length ($file_name_utf16) + 1 + 2; # +1 for "external" info, + 2 for end of string

  $ret .= add_number ($property_size);

  $external = 0;

  $ret .= add_number ($external);

  $ret .= $file_name_utf16;

  $ret .= "\x00\x00";


  # DUMMY:

  # $property_type = $SEVEN_ZIP_DUMMY;  # really needed ? just for alignment ?

  # $ret .= $property_type;

  # $property_size = 0; # this is a little trick: it only adds 2 bytes (ID and len = 0)

  # $ret .= add_number ($property_size);

  # $ret .= "\x00" x $property_size;


  # MODIFICATION TIME:

  $property_type = $SEVEN_ZIP_MODIFICATION_TIME;

  $ret .= $property_type;

  $property_size = 1 + 1 + 8; # = 10 (defined + external + uint64)

  $ret .= add_number ($property_size);

  # get_uint64_defined_vector ()

  $ret .= $SEVEN_ZIP_ALL_DEFINED; # \x01, defined (for each file)

  $external = 0;

  $ret .= add_number ($external);

  my $modification_time = $first_file->{'modification_time'};

  for (my $i = 0; $i < 8; $i++)
  {
    $ret .= chr ($modification_time & 0xff);

    $modification_time >>= 8;
  }


  # ATTRIBUTES (file attributes NTFS/UNIX):

  $property_type = $SEVEN_ZIP_WIN_ATTRIBUTE; # file attributes !!!

  $ret .= $property_type;

  $property_size = 1 + 1 + 4;

  $ret .= add_number ($property_size);

  $ret .= $SEVEN_ZIP_ALL_DEFINED; # \x01: all defined

  $external = 0;

  $ret .= add_number ($external);

  # for each file actually:

  my $file_attribute = $first_file->{'attribute'};

  $ret .= pack ("L<", $file_attribute);


  # END:

  $ret .= $SEVEN_ZIP_END; # end of properties loop


  $ret .= $SEVEN_ZIP_END; # end of seven_zip_files_info (read_seven_zip_files_info ()):

  return $ret;
}

sub seven_zip_signature_header
{
  my $signature_header = shift;
  my $header_crc       = shift;

  my $ret = "";

  my $major_version = $signature_header->{'major_version'};

  $ret .= chr ($major_version);

  my $minor_version = $signature_header->{'minor_version'};

  $ret .= chr ($minor_version);

  my $signature_header_buf = "";


  my $tmp_val;

  $tmp_val = $signature_header->{'next_header_offset'};

  for (my $i = 0; $i < 8; $i++)
  {
    $signature_header_buf .= chr ($tmp_val & 0xff);

    $tmp_val >>= 8;
  }


  $tmp_val = $signature_header->{'next_header_size'};

  for (my $i = 0; $i < 8; $i++)
  {
    $signature_header_buf .= chr ($tmp_val & 0xff);

    $tmp_val >>= 8;
  }


  $tmp_val = $header_crc;

  for (my $i = 0; $i < 4; $i++) # or use: $signature_header_buf .= pack ("L<",  $header_crc)
  {
    $signature_header_buf .= chr ($tmp_val & 0xff);

    $tmp_val >>= 8;
  }

  my $signature_crc = crc32 ($signature_header_buf);

  $ret .= pack ("L<", $signature_crc);

  $ret .= $signature_header_buf;

  return $ret;
}

sub extracted_hash_to_archive
{
  my $hash      = shift;
  my $line_num  = shift;
  my $main_name = shift;
  my $mod_time  = shift;
  my $chmod     = shift;

  my @fields = split (/\$/, $hash);

  if (! @fields)
  {
    print STDERR "ERROR: malformed hash on line $line_num, too few hash fields\n";

    return "";
  }

  my $fields_num = scalar (@fields);

  if ($fields_num < $SEVEN_ZIP_MIN_HASH_FIELD_NUM)
  {
    print STDERR "ERROR: malformed hash on line $line_num, too few hash fields\n";

    return "";
  }

  if ($fields_num > $SEVEN_ZIP_MAX_HASH_FIELD_NUM)
  {
    print STDERR "ERROR: malformed hash on line $line_num, too many hash fields\n";

    return "";
  }

  my $type_of_data     = $fields[ 2];
  my $num_cycles_power = $fields[ 3];
  my $salt_len         = $fields[ 4];
  my $salt_buf         = $fields[ 5];
  my $iv_len           = $fields[ 6];
  my $iv_buf           = $fields[ 7];
  my $crc              = $fields[ 8];
  my $data_len         = $fields[ 9];
  my $unpack_size      = $fields[10];
  my $data             = $fields[11];

  my $crc_len = 0;
  my $additional_attributes = "";

  if ($type_of_data !~ m/^[0-9]+$/)
  {
    print STDERR "ERROR: malformed hash on line $line_num, invalid type of data '$type_of_data'\n";

    return "";
  }

  if (($type_of_data != $SEVEN_ZIP_UNCOMPRESSED) &&
      ($type_of_data != $SEVEN_ZIP_TRUNCATED))
  {
    if ($fields_num < ($SEVEN_ZIP_MIN_HASH_FIELD_NUM + 1))
    {
      print STDERR "ERROR: malformed hash on line $line_num, missing crc length and attributes\n";

      return "";
    }

    $crc_len               = $fields[12];
    $additional_attributes = $fields[13];

    if (! defined ($additional_attributes))
    {
      $additional_attributes = "";
    }

    if ($fields_num > ($SEVEN_ZIP_MIN_HASH_FIELD_NUM + 2))
    {
      $additional_attributes .= "\$" . $fields[14];
    }
  }

  if ($salt_buf !~ m/^[0-9a-fA-F]*$/) # can be empty
  {
    print STDERR "ERROR: malformed hash on line $line_num, non hexadecimal salt\n";

    return "";
  }

  if ($iv_buf !~ m/^[0-9a-fA-F]+$/)
  {
    print STDERR "ERROR: malformed hash on line $line_num, non hexadecimal IV\n";

    return "";
  }

  if ($data !~ m/^[0-9a-fA-F]+$/)
  {
    print STDERR "ERROR: malformed hash on line $line_num, non hexadecimal data\n";

    return "";
  }

  $salt_buf = pack ("H*", $salt_buf);
  $iv_buf   = pack ("H*", $iv_buf);
  $data     = pack ("H*", $data);

  $iv_buf = substr ($iv_buf, 0, $iv_len); # needed because we have a fixed length/padded field

  my @parsed_attributes = ();

  if (length ($additional_attributes) > 0)
  {
    my @additional_attributes_split = split (/\$/, $additional_attributes);

    my $num_attributes = scalar (@additional_attributes_split);

    # very special case (preprocessor used after coder, VERY SELDOM):

    my $potential_preprocessor_after_coder = -1;

    if (substr ($additional_attributes, 0, 1) eq ",") # special case
    {
      if ($num_attributes == 2) # we have coders and preprocessors
      {
        my @attrs = split (/,/, $additional_attributes_split[0]);

        if (scalar (@attrs) > 0)
        {
          my @type_and_order = split (/_/, $attrs[1]);

          my $type = $type_and_order[0] >> 4;  # this attribute

          # two coders "next to each other" with the same ID => hit:

          if ($type == ($type_of_data & 0x0f)) # compare w/ main type_of_data (after $7z$)
          {
            $potential_preprocessor_after_coder = $type;
          }
        }
      }
    }

    my $order = 0; # increasing order (smaller value for higher priority)
    my $type  = 0; # compressor or preprocessor

    for (my $i = 0; $i < $num_attributes; $i++)
    {
      my @attrs = split (/,/, $additional_attributes_split[$i]);

      my $is_preprocessor = int ($i == 1); # or: $i > 0

      my $attr_num = scalar (@attrs);

      # special case (empty attribute value):

      if ($attr_num < 1)
      {
        $attr_num = 1; # MIN
        $attrs[0] = "";
      }

      for (my $j = 0; $j < $attr_num; $j++)
      {
        my $str = $attrs[$j];

        my $separator_pos = index ($str, "_");

        my $codec_id = 0;

        if ($separator_pos >= 0)
        {
          my $type_and_order = substr ($str, 0, $separator_pos);

          if ($type_and_order !~ m/^[0-9]+$/)
          {
            print STDERR "ERROR: type and order for hash on line $line_num is invalid\n";

            return "";
          }

          $type_and_order = int ($type_and_order);

          $codec_id = $type_and_order >>   4;
          $order    = $type_and_order  & 0xf;

          # second parameter (the attributes themself):

          $str = substr ($str, $separator_pos + 1);
        }
        else
        {
          if ($is_preprocessor == 1)
          {
            $codec_id = ($type_of_data >> 4) & 0xf;
          }
          else
          {
            $codec_id = ($type_of_data >> 0) & 0xf;
          }
        }

        my $order_mod = $order; # don't modify original value (which is always increasing)

        my $skip = 0;

        if ($potential_preprocessor_after_coder != -1)
        {
          if ($j == 0) # only valid for first attribute (i.e. "," at the start)
          {
            if ($type == 0) # compressors / decompressor
            {
              if ($codec_id == $potential_preprocessor_after_coder)
              {
                $skip = 1; # only if first main coder ($j == 0) !
              }
            }
            else
            {
              $order_mod = 0; # must always be zero (i.e. first preprocessor before first coder)

              $potential_preprocessor_after_coder = -1; # reset
            }
          }
        }

        if ($skip == 1)
        {
          next;
        }

        my $item =
        {
          "id"    => $codec_id,
          "type"  => $type,
          "order" => $order_mod,
          "attrs" => pack ("H*", $str),
        };

        push (@parsed_attributes, $item);

        $order++;
      }

      $type++;
    }
  }

  # AES:

  if ($type_of_data == $SEVEN_ZIP_TRUNCATED) # padding attack
  {
    print STDERR "ERROR: hash on hash line $line_num uses the padding attack and ";
    print STDERR "therefore does nat have the full information we need\n";

    return "";
  }

  my $min_num_coders = 1; # always SEVEN_ZIP_AES

  if ((($type_of_data >> 0) & 0x0f) != 0) # main coder
  {
    $min_num_coders++;
  }

  if ((($type_of_data >> 4) & 0x0f) != 0) # preprocessor
  {
    $min_num_coders++;
  }

  my $num_parsed_attributes = scalar (@parsed_attributes);

  my $num_coders = $num_parsed_attributes + 1; # +1 for AES

  if ($min_num_coders > $num_coders)
  {
    $num_coders = $min_num_coders;
  }

  my $iv_len_mod = $iv_len - 1;

  if ($iv_len_mod < 0) # can't get negative (values of $iv_len < 1 not supported by 7-Zip ?)
  {
    print STDERR "WARNING: hash on line $line_num has a IV length < 1, this might not be ";
    print STDERR "supported by the 7-Zip format\n";

    $iv_len_mod = 0;
  }

  my $seven_zip_aes_attributes = chr ($SEVEN_ZIP_AES_DEFAULT_ATTRIBUTES + $num_cycles_power)
                               . chr ($iv_len_mod)
                               . $iv_buf;

  my $folders =
  [
    {
      'sum_input_streams'  => $num_coders, # min: 2
      'sum_output_streams' => $num_coders, # min: 2
      'sum_packed_streams' => 1,
      'index_main_stream'  => 1,
      'number_coders'      => $num_coders, # min: 2
      'coders' =>
       [
         {
           'number_output_streams' => 1,
           'number_input_streams'  => 1,
           'codec_id'   => $SEVEN_ZIP_AES,
           'attributes' => $seven_zip_aes_attributes,
         },
       ],
      'bindpairs' => []
    }
  ];

  for (my $i = 0; $i < $num_coders - 1; $i++) # or $folders->{'sum_output_streams'} - 1
  {
    # note: last coders output is next coders input (in general) !

    $folders->[0]->{'bindpairs'}->[$i] = [$i + 1, $i]; # format is: [input_index, output_index]
  }

  my $coder_arr_pos = 1;

  foreach my $c (sort {$a->{'order'} > $b->{'order'}} @parsed_attributes)
  {
    my $id = $SEVEN_ZIP_CODEC_IDS->[$c->{'type'}]{$c->{'id'}};

    if (! defined ($id))
    {
      print STDERR "ERROR: unknown codec id " . $c->{'type'} . " / " . $c->{'id'} . " ";
      print STDERR "on hash in line $line_num\n";

      return "";
    }

    $folders->[0]->{'coders'}->[$coder_arr_pos] =
    {
      'number_output_streams' => 1,
      'number_input_streams'  => 1,
      'codec_id'   => $id,
      'attributes' => $c->{'attrs'},
    };

    $coder_arr_pos++;
  }

  # special case: add enough empty coders for our main coder/preprocessor:
  # (even if there could be no additional attribute lists for them)

  if (($min_num_coders - 1) > $num_parsed_attributes)
  {
    my $main_coder_id   = ($type_of_data >> 0) & 0x0f;
    my $preprocessor_id = ($type_of_data >> 4) & 0x0f;

    my @main_coder_ids   = values (%{$SEVEN_ZIP_CODEC_IDS->[0]});
    my @preprocessor_ids = values (%{$SEVEN_ZIP_CODEC_IDS->[1]});

    my $has_main_coder        = 0;
    my $has_main_preprocessor = 0;

    for (my $i = 0; $i < $coder_arr_pos; $i++)
    {
      my $coder    = $folders->[0]->{'coders'}->[$i];
      my $codec_id = $coder->{'codec_id'};

      for (my $j = 0; $j < scalar (@main_coder_ids); $j++)
      {
        if ($codec_id eq $main_coder_ids[$j])
        {
          $has_main_coder = 1;

          last;
        }
      }

      for (my $j = 0; $j < scalar (@preprocessor_ids); $j++)
      {
        if ($codec_id eq $preprocessor_ids[$j])
        {
          $has_main_preprocessor = 1;

          last;
        }
      }
    }

    if ($has_main_coder == 0)
    {
      if ($main_coder_id != 0) # main coder
      {
        my $id = $SEVEN_ZIP_CODEC_IDS->[0]{$main_coder_id};

        if (! defined ($id))
        {
          print STDERR "ERROR: unknown codec id 0 / " . $main_coder_id . " ";
          print STDERR "on hash in line $line_num\n";

          return "";
        }

        $folders->[0]->{'coders'}->[$coder_arr_pos] =
        {
          'number_output_streams' => 1,
          'number_input_streams'  => 1,
          'codec_id'   => $id,
          'attributes' => '',
        };

        $coder_arr_pos++;
      }
    }

    if ($has_main_preprocessor == 0)
    {
      if ($preprocessor_id != 0) # preprocessor
      {
        my $id = $SEVEN_ZIP_CODEC_IDS->[1]{$preprocessor_id};

        if (! defined ($id))
        {
          print STDERR "ERROR: unknown codec id 1 / " . $preprocessor_id . " ";
          print STDERR "on hash in line $line_num\n";

          return "";
        }

        $folders->[0]->{'coders'}->[$coder_arr_pos] =
        {
          'number_output_streams' => 1,
          'number_input_streams'  => 1,
          'codec_id'   => $id,
          'attributes' => '',
        };

        $coder_arr_pos++;
      }
    }
  }


  my $substreams_info;

  $substreams_info->{'unpack_stream_numbers'}   = [ 1 ];
  $substreams_info->{'number_digests'}          = 1;
  $substreams_info->{'digests'}[0]->{'defined'} = 1;
  $substreams_info->{'digests'}[0]->{'crc'}     = $crc;
  $substreams_info->{'unpack_sizes'}[0]         = $crc_len;

  my $pack_info;

  $pack_info->{'number_pack_streams'} = 1;
  $pack_info->{'pack_pos'}            = 0;
  $pack_info->{'pack_sizes'}[0]       = $data_len;

  my $unpack_info;

  $unpack_info->{'number_folders'}         = 1; # scalar (@$folders);
  $unpack_info->{'folders'}                = $folders;
  $unpack_info->{'datastream_indices'}     = [];
  $unpack_info->{'digests'}                = [];
  $unpack_info->{'main_unpack_size_index'} = [ 1 ];
  $unpack_info->{'unpack_sizes'}           = [ $unpack_size, $crc_len ];
  $unpack_info->{'coder_unpack_sizes'}     = [ 0 ];

  # we need to add the "unpack_sizes" for each coder, but we do NOT have all the lengths within
  # the hashcat 7z hash format, therefore we need to try if just adding the last known length
  # (i.e. $crc_len) works for us:

  for (my $i = 2; $i < $num_coders; $i++) # or $folders->{'sum_output_streams'}
  {
    $unpack_info->{'unpack_sizes'}->[$i] = $crc_len; # last entry
  }

  my $signature_header;

  $signature_header->{'major_version'}         =   0;
  $signature_header->{'minor_version'}         =   4;
  $signature_header->{'position_after_header'} = $SEVEN_ZIP_SIGNATURE_LEN;
  $signature_header->{'next_header_size'}      = 106; # dynamically changed
  $signature_header->{'next_header_offset'}    = $data_len;

  my $streams_info;

  $streams_info->{'substreams_info'} = $substreams_info;
  $streams_info->{'unpack_info'}     = $unpack_info;
  $streams_info->{'pack_info'}       = $pack_info;

  my $unix_timestamp = time ();

  if ($mod_time != -1)
  {
    $unix_timestamp = $mod_time;
  }

  my $modification_time = ($unix_timestamp + $SEVEN_ZIP_TIME_OFFSET) * 10000000;

  my $file_permission = 0; # or hard-code it like: 2176090144 (-rw-rw-r--)

  $file_permission |= 0b0000000000100000 <<  0; # FILE_ATTRIBUTE_ARCHIVE (not directory = 0b10000)
  $file_permission |= 0b1000000000000000 <<  0; # FILE_ATTRIBUTE_UNIX_EXTENSION (0x8000)
  $file_permission |= 0b1000000000000000 << 16; # start of st_mode & 0xffff: S_IFREG=regular, stat.h

  # 000...777 (3 times r w x, +4 +2 +1, user (u), group (g), others (o))

  my $octal_chmod = oct ($SEVEN_ZIP_FILE_PERMISSION); # 664, -rw-rw-r--

  if ($chmod != -1)
  {
    $octal_chmod = oct ($chmod);
  }

  $file_permission |= $octal_chmod << 16; # "highAttrib" for UNIX EXTENSION

  # Examples:
  # $file_permission = 2176090144; # -rw-rw-r--
  # $file_permission = 2176221216; # -rw-rw-rw-
  # $file_permission = 2166652961; # -r--r--r--
  # $file_permission = 2180874272; # -rwxrwxr-x
  # $file_permission = 2181005344; # -rwxrwxrwx
  # $file_permission = 2180939808; # -rwxrwxrw-
  # $file_permission = 2180808736; # -rwxrwxr--
  # $file_permission = 2180546592; # -rwxrwx---
  # $file_permission = 2180022304; # -rwxrw----
  # $file_permission = 2178973728; # -rwxr-----
  # $file_permission = 2176876576; # -rwx------
  # $file_permission = 2172682272; # -rw-------
  # $file_permission = 2164293665; # -r--------
  # $file_permission = 2147516449; # ----------

  # other attributes: setuid (u+s) / setgid (g+s) / sticky bit (+t)

  my $files =
  [
    {
      'start_position'    => 0,
      'name_utf16'        => $main_name,
      'is_dir'            => 0,
      'is_empty_stream'   => 0,
      'has_stream'        => 1,
      'size'              => $unpack_size,
      'crc'               => $crc,
      'crc_defined'       => 1,
      'attribute_defined' => 1,
      'attribute'         => $file_permission,
      'modification_time' => $modification_time,
      'creation_time'     => 0,
      'access_time'       => 0,
    }
  ];

  my $files_info;

  $files_info->{'number_files'} = 1;
  $files_info->{'files'}        = $files;

  my $parsed_header;

  $parsed_header->{'type'}                    = 'raw';
  $parsed_header->{'streams_info'}            = $streams_info;
  $parsed_header->{'files_info'}              = $files_info;
  $parsed_header->{'additional_streams_info'} = undef;

  # my $archive;

  # $archive->{'signature_header'} = $signature_header;
  # $archive->{'parsed_header'}    = $parsed_header;


  my $header = seven_zip_header ($parsed_header);

  my $header_crc = crc32 ($header);


  # update of "next header size" needed for file header (here also called signature header):

  $signature_header->{'next_header_size'} = length ($header);


  my $signature = seven_zip_signature_header ($signature_header, $header_crc);


  my $data_bin = "";

  $data_bin .= $SEVEN_ZIP_MAGIC;
  $data_bin .= $signature;
  $data_bin .= $data;
  $data_bin .= $header;

  return $data_bin;
}

sub write_output_file
{
  my $data_buf  = shift;
  my $file_name = shift;

  print "Writing " . length ($data_buf) . " bytes to file '$file_name'.\n";

  # DEBUG:
  # print unpack ("H*", $data_buf) . "\n";


  # file writing:

  my $out_file;

  if (! open ($out_file, ">", $file_name))
  {
    print STDERR "ERROR: could not open file '$file_name' for writing\n";

    exit (1);
  }

  binmode ($out_file);

  print $out_file $data_buf;

  close ($out_file);
}

sub extract_argv
{
  my $argc = shift;
  my $pos  = shift;
  my $exp  = shift; # array of expected values (always short and long, 2 items)

  if ($pos >= $argc)
  {
    print STDERR "ERROR: missing command line argument at position $pos\n";

    exit (1);
  }

  my $arg = $ARGV[$pos];

  if ($arg =~ m/^$$exp[0]=?$/ || # only 1 argument, e.g. -t=0 or --time0
      $arg =~ m/^$$exp[1]=?$/)
  {
    $pos++;

    if ($pos >= $argc)
    {
      print STDERR "ERROR: value for argument '$$exp[0]' is missing\n";

      exit (1);
    }

    $arg = $ARGV[$pos];
  }
  else
  {
    $arg =~ s/^$$exp[0]=?//;
    $arg =~ s/^$$exp[1]=?//;
  }

  if (length ($arg) < 1)
  {
    print STDERR "ERROR: value for argument '$$exp[0]' is missing\n";

    exit (1);
  }

  return ($arg, $pos);
}

sub usage
{
  my $executable_name = shift;

  print "Usage: " . $executable_name . " [Option]... [hash_file]...\n";

  print "\n";

  print "[ Option ]\n\n";

  print "Options Short, Long | Type | Description                                  | Example\n";
  print "====================+======+==============================================+=========\n";
  print "-v, --version       |      | Print version                                |\n";
  print "-h, --help          |      | Print help                                   |\n";
  print "-o, --output        | Str  | File to write to (output 7-Zip archive file) | -o ab.7z\n";
  print "-n, --name          | Str  | Name of the file used within the 7-Zip file  | -n a.bin\n";
  print "-t, --time          | Num  | Unix modification time of the main file      | -t 99999\n";
  print "-c, --chmod         | Num  | Unix chmod octal file permission             | -c 600\n";
  print "--                  |      | Stops parsing command line arguments         |\n";
  print "\n";
}

sub version_short
{
  print $TOOL_VERSION . "\n";
}

sub version_long
{
  print "$TOOL_NAME $TOOL_VERSION\n";
  print "License: public domain, credits go to philsmd and hashcat\n\n";

  print "Written by philsmd (a 7z2hashcat and hashcat developer)\n";
}


#
# Start
#

# Check if there are some command line parameters:

my $output_name_arg       = $SEVEN_ZIP_OUTPUT_NAME;
my $main_file_name_arg    = "";
my $modification_time_arg = -1;
my $chmod_arg             = -1;

my $stop_accepting_arguments = 0;

my @hash_files = ();

my $argc = scalar (@ARGV);

for (my $i = 0; $i < $argc; $i++)
{
  my $arg = $ARGV[$i];

  if ($stop_accepting_arguments == 1)
  {
    push (@hash_files, $arg);
  }
  elsif ($arg !~ m/^-/) # for sure not a command line switch/option
  {
    push (@hash_files, $arg);
  }
  elsif ($arg =~ m/^--$/)
  {
    $stop_accepting_arguments = 1;
  }
  elsif ($arg =~ m/^-h$/ ||
         $arg =~ m/^--help$/)
  {
    usage ($0);

    exit (0);
  }
  elsif ($arg =~ m/^-v$/ ||
         $arg =~ m/^-V$/)
  {
    version_short ();

    exit (0);
  }
  elsif ($arg =~ m/^--version$/)
  {
    version_long ();

    exit (0);
  }
  elsif ($arg =~ m/^-o.*$/ ||
         $arg =~ m/^--output.*$/)
  {
    ($output_name_arg, $i) = extract_argv ($argc, $i, ["-o", "--output"]);
  }
  elsif ($arg =~ m/^-n.*$/ ||
         $arg =~ m/^--name.*$/)
  {
    ($main_file_name_arg, $i) = extract_argv ($argc, $i, ["-n", "--name"]);
  }
  elsif ($arg =~ m/^-t.*$/ ||
         $arg =~ m/^--time.*$/)
  {
    ($modification_time_arg, $i) = extract_argv ($argc, $i, ["-t", "--time"]);

    if ($modification_time_arg !~ m/^[0-9]+$/)
    {
      print STDERR "ERROR: invalid unix time stamp for argument -t\n";

      exit (1);
    }
  }
  elsif ($arg =~ m/^-c.*$/ || # -c with just 1 argument (e.g. -c777)
         $arg =~ m/^--chmod.*$/)
  {
    ($chmod_arg, $i) = extract_argv ($argc, $i, ["-c", "--chmod"]);

    # 000...777 (3 times r w x, +4 +2 +1, user (u), group (g), others (o))

    if ($chmod_arg !~ m/^[0-7][0-7][0-7]$/)
    {
      print STDERR "ERROR: invalid octal file permission for argument -c (000...777)\n";

      exit (1);
    }
  }
  else
  {
    print STDERR "ERROR: unknown command line argument '$arg'\n\n";

    usage ($0);

    exit (1);
  }
}

# special case (no input hash file):

if (scalar (@hash_files) < 1)
{
  push (@hash_files, undef); # add STDIN
}


#
# main loop (loop over all hash files):
#

foreach my $hash_file_name (@hash_files)
{
  my $fh;

  if (defined ($hash_file_name) == 1)
  {
    if (! open ($fh, "<", $hash_file_name))
    {
      print STDERR "ERROR: could not open file '$hash_file_name'\n";

      next;
    }
  }
  else
  {
    # special case (open STDIN):

    if (! open ($fh, "-"))
    {
      print STDERR "ERROR: could not read input from STDIN\n";

      next;
    }

    print STDERR "NOTE: reading data from STDIN, specify a command line argument ";
    print STDERR "if you do NOT intend to do this\n";
  }

  # following operation is not needed, we have a hexadecimal/ascii hash format:
  # binmode ($fh);

  my $line_num = 0;

  while (my $line = <$fh>)
  {
    chomp ($line);

    $line_num++;

    next if (length ($line) < 1); # ignore empty lines

    if (length ($line) < 4)
    {
      print STDERR "ERROR on line $line_num: Hash line too short\n";

      next;
    }

    my $seven_zip_file_name_in_line = "";

    my $signature = substr ($line, 0, 4);

    if ($signature ne $SEVEN_ZIP_HASH_SIGNATURE)
    {
      # check additional special case (exception for file names within the hash lines):

      my $signature_pos = index ($line, ":" . $SEVEN_ZIP_HASH_SIGNATURE);

      if ($signature_pos < 0) # both cases didn't work => error
      {
        print STDERR "ERROR on line $line_num: No valid hash signature found ";
        print STDERR "($signature vs $SEVEN_ZIP_HASH_SIGNATURE)\n";

        next;
      }

      # special case, we have the file name directly within the hash line (we therefore use it):

      $seven_zip_file_name_in_line = substr ($line, 0, $signature_pos);

      $line = substr ($line, $signature_pos + 1);
    }


    # file name used as the first/main name of files for our output 7-Zip file:

    my $main_file_name = $SEVEN_ZIP_FILE_NAME;

    if ($main_file_name_arg ne "")
    {
      my $main_file_name_len = length ($main_file_name_arg);

      # (trivial/incorrect) UTF16 detection:

      my $is_utf_16 = 0;

      for (my $i = 1; $i < $main_file_name_len; $i += 2) # every 2nd byte should be \x00
      {
        my $c = substr ($main_file_name_arg, $i, 1);

        if ($c eq "\x00")
        {
          $is_utf_16 = 1;

          last;
        }
      }

      # (trivial/incorrect) UTF16 conversion:

      if ($is_utf_16 == 0) # always the case, in general no UTF16 usage in command line
      {
        $main_file_name = "";

        for (my $i = 0; $i < $main_file_name_len; $i++)
        {
          $main_file_name .= substr ($main_file_name_arg, $i, 1) . "\x00";
        }
      }
      else
      {
        $main_file_name = $main_file_name_arg;
      }
    }


    #
    # Most important function call:
    #

    my $file_name = $main_file_name;
    my $mod_time  = $modification_time_arg;
    my $chmod     = $chmod_arg;

    my $bin_data = extracted_hash_to_archive ($line, $line_num, $file_name, $mod_time, $chmod);


    if (length ($bin_data) < 1)
    {
      # exact error message was already mentioned in extracted_hash_to_archive ()

      next;
    }


    # determining final file name (could be multiple output files in total, with count):

    my $seven_zip_file_name = $output_name_arg;

    if ($seven_zip_file_name_in_line ne "")
    {
      $seven_zip_file_name = $seven_zip_file_name_in_line;
    }

    if ($seven_zip_file_name !~ m/\.$SEVEN_ZIP_FILE_EXTENSION$/)
    {
      $seven_zip_file_name .= "." . $SEVEN_ZIP_FILE_EXTENSION;
    }

    while (-f $seven_zip_file_name)
    {
      $seven_zip_file_name =~ s/\.$SEVEN_ZIP_FILE_EXTENSION$//;

      my $file_count = 1;

      if ($seven_zip_file_name =~ m/([0-9]+)$/)
      {
        $file_count = int ($1) + 1;

        $seven_zip_file_name =~ s/[0-9]*$//;
      }

      $seven_zip_file_name .= $file_count . "." . $SEVEN_ZIP_FILE_EXTENSION;
    }

    write_output_file ($bin_data, $seven_zip_file_name);
  }

  if (defined ($hash_file_name) == 1) # do NOT close STDIN
  {
    close ($fh);
  }
}
