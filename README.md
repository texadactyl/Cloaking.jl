# Cloaking.jl

#### OVERVIEW

This project constitutes a file cloaking utility that provides password-based security of a single file or a single file system archive file (E.g. .tar.gz). The utility is probably most useful in the following situations:

* Storing backups of sensitive information on the Internet
* Transporting sensitive information electronically (E.g. email) or manually (E.g. using a flash drive)

This project is dependent on Nettle.jl, using:

* Password-based Key Derivation Function version 2 (PBKDF2)
* AES256 data cryptography in Cipher-Block Chaining (CBC) mode
* Hash-based Message Authentication Code (HMAC) function SHA512

Nettle.jl reference: https://github.com/JuliaCrypto/Nettle.jl

#### REQUIREMENTS

* Julia JIT
* Nettle.jl

#### INSTALLATION ####
```
#!/usr/bin/bash

cat <<EOF | julia
import Pkg
Pkg.add(url = "https://github.com/texadactyl/Cloaking.jl")
EOF
```

#### LICENSING

This is NOT commercial software; instead, usage is covered by the GNU General Public License version 3 (2007). In a nutshell, please feel free to use the project and share it as you will but please don't sell it. Thank you!

See the LICENSE file for the GNU licensing information.

#### SAMPLE CALLING PROGRAM

See the test program, test/test_cases.jl.

#### CIPHERTEXT ANATOMY

The ciphertext file created by cloak_file() has the following layout:

    TIFF prefix to make the file appear as a TIFF (112 bytes)
    Initialization Vector (16 bytes)
    Original file size as a binary Big Endian Unsigned Long Long (8 bytes)
    "BOUNDARY" as a UInt8 bytearray (8 bytes)
    Encrypted file data 
        (last cleartext block is padded if necessary to a 16-byte boundary)
    HMAC bytearray (64 bytes)
    ==========================
    Total overhead = 208 bytes

Feel free to add an issue for inquiries and bugs. I'll respond as soon as I can.

Richard Elkins 

Dallas, Texas, USA, 3rd Rock, Sol, ...
