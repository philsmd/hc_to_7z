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

# Proof of concept / experimential warning

Please be aware that this tool is highly experimential and was originally meant only as a POC (proof of concept) to help convert some `hashcat` users's hashes back to working `.7z` files, for debugging purposes.

The support of unusual and more advanced combinations of `coders` and `preprocessors` (see `7z2hashcat` README from https://github.com/philsmd/7z2hashcat) is not supported yet (or only very limited support was added, untested).

With the original `7z` file (i.e. having/obtaining the 7-Zip instead of only the hash file), it would be possible to debug/troubleshoot the conversion such that you can help to add many, many more features and debug `hc_to_7z` to make the file written by `hc_to_7z` almost identical to the input file.

Being a POC, a lot of small refactorings would be required (especially to avoid many large functions, introduce much more helper functions, avoid duplication of code etc) to make the code more readable and stable, this (quick) implementation of course was not focusing on making the code easy to read and easy to understand. A little bit of refactoring would fix this problem easily.

Please also note that the external tool `7z2hashcat` does **not** convert the file to a hash without losing information. The transformation/conversion by `7z2hashcat` is lossy / **not lossless** and therefore `hc_to_7z` can never have all the correct information (including original file names etc). Many values, properties and attributes used by `hc_to_7z` will therefore just be constant values or dynamically implied/guessed/calculated/determined values.

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
