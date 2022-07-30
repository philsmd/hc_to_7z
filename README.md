# About

The goal of this project is to have a tool that can be used to convert -m 11600 = `7-Zip` `hashcat` hashes back to `.7z` files, that can be opened with standard archive tools/viewers like `p7zip`/`7z`/`ark` etc. The input to this `hc_to_7z` tool is the output of `7z2hashcat` from https://github.com/philsmd/7z2hashcat

# Requirements

Software:  
- Perl must be installed (should work on *nix and windows with perl installed)
- Perl module "Digest::CRC" is required
    - example on how to install it on ubuntu:  
    `sudo apt install libdigest-crc-perl`  
    or  
    `sudo cpan Digest::CRC`

# Installation and first steps

* Clone this repository:  
    ```git clone https://github.com/philsmd/hc_to_7z```
* Enter the repository root folder:  
    ```cd hc_to_7z```
* Run it:  
    ```perl hc_to_7z.pl hashes.txt```
* Open the file mentioned within your terminal/shell with your preferred archive tool/viewer

# Command line parameters

The usage is very simple: you just specify the path to the 7-Zip hash file as the first command line argument.  
  
You can also use multiple files on the command line like this:  
```
perl hc_to_7z.pl hash*.txt
perl hc_to_7z.pl hash_files/*
```
   
   
More example commands:
```
perl hc_to_7z.pl hash.txt
perl hc_to_7z.pl --version
perl hc_to_7z.pl --help
perl hc_to_7z.pl -o output.7z hash.txt
perl hc_to_7z.pl -o jingle.wav.7z -n jingle.wav hash.txt
```

# Proof of concept / experimental warning

Please be aware that this tool is highly experimental and was originally meant only as a POC (proof of concept) to help convert some `hashcat` users's hashes back to working `.7z` files, for debugging purposes.

The support of unusual and more advanced combinations of `coders` and `preprocessors` (see `7z2hashcat` README from https://github.com/philsmd/7z2hashcat) is not supported yet (or only very limited support was added, untested).

With the original `7z` file (i.e. having/obtaining the 7-Zip instead of only the hash file), it would be possible to debug/troubleshoot the conversion such that you can help to add many, many more features and debug `hc_to_7z` to make the file written by `hc_to_7z` almost identical to the input file.

Being a POC, a lot of small refactorings would be required (especially to avoid many large functions, introduce much more helper functions, avoid duplication of code etc) to make the code more readable and stable, this (quick) implementation of course was not focusing on making the code easy to read and easy to understand. A little bit of refactoring would fix this problem easily.

Please also note that the external tool `7z2hashcat` does **not** convert the file to a hash without losing information. The transformation/conversion by `7z2hashcat` is lossy / **not lossless** and therefore `hc_to_7z` can never have all the correct information (including original file names etc). Many values, properties and attributes used by `hc_to_7z` will therefore just be constant values or dynamically implied/guessed/calculated/determined values.

# Integrity test failure

Sometimes the so-called "integrity test" that is offered/available by some tools, when you run it on the file written by `hc_to_7z`, could fail. This is normally only the case whenever the original archive had more than 1 file compressed and encrypted and they all were part of the same `7z stream` data. This could happen if you have multiple files and a single `stream` "compresses" all of them with one coder (compression algorithm, like `LZMA2`).

Therefore, we would need to both decrypt and decompress the data to see what the raw data of the first file would be (we know only the first file's length) and then we would either need to re-compress and re-encrypt the data, which is `stream data` belonging to more files, with just the raw data of the first file - but this could be considered a little bit of cheating, because we would actually change the original file data -, or use this information to indicate within the written `7-Zip` file, that we have 2+ files with specific file lengths (but we can't be 100% sure where the next boundaries are, between file 2 and file 3 etc).

Unfortunately, `7z2hashcat` itself does not give us all of this information, i.e. we do not know all the file lengths for each and every file belonging to the same stream, we only know the length of the **first** file.

That said, the data for the first file within the output file, written by `hc_to_7z`, should still be 100% complete and correct (we know this also by the first file's CRC32 checksum), it is just the "extra data" of this "stream" that will make the integrity test (e.g. `7z t tmp.7z`) fail (but fortunately most tools can still extract the data correctly, even if there is "more data"), i.e. data which would normally belong to the next (second, third, ...) files.

We can't easily fix this, because a fix would only make sense if either `7z2hashcat` outputs much more info, or if we try to perform even more advanced parsing of the data, i.e. decryption/decoding/decompression/pre-processing within `hc_to_7z` of this `stream` data. It would be a little bit exaggerated to do all this in this POC tool (we would need to add many compression/decompression algorithms and pre-processing filters in this perl script, like `LZMA2`, `Delta` etc), just to make the `integrity test` not fail.

# Hacking / Missing features

* More features
* CLEANUP the code, refactor, use more coding standards, make it easier readable, everything is welcome (submit patches!)
* keep it up-to-date with `7z2hashcat`
* improvements and all bug fixes are very welcome
* solve and remove the TODOs (if any exist)
* and,and,and

# Credits and Contributors

Credits go to:  
  
* philsmd, hashcat project

# License/Disclaimer

License: belongs to the PUBLIC DOMAIN, donated to hashcat, credits MUST go to hashcat and philsmd for their hard work. Thx  
  
Disclaimer: WE PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
NO GUARANTEES THAT IT WORKS FOR YOU AND WORKS CORRECTLY
