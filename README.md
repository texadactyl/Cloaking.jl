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

* Julia JIT Compiler
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

#### API DEMONSTRATION

Julia source code:
```
println("demo_cloaking: Install Cloaking.jl from github .....")
import Pkg
Pkg.add(url = "https://github.com/texadactyl/Cloaking.jl")
println("demo_cloaking: Installation completed.")

using Printf
using Cloaking

SECRET = "/etc/hosts"

CLEARTEXT_1 = "/etc/mime.types"
CIPHERTEXT = "/tmp/ciphertext.tiff"
CLEARTEXT_2 = "/tmp/recovered_cleartext.txt"

password = open(SECRET) do file
    read(file, String)
end

println("demo_cloaking: Cloaking .....")
et, ncipherbytes = cloak_file(password, CLEARTEXT_1, CIPHERTEXT)
@printf("cloak_file E.T. = %d s, # of encrypted bytes = %d\n", et, ncipherbytes)

println("demo_cloaking: Uncloaking .....")
et, nclearbytes = uncloak_file(password, CIPHERTEXT, CLEARTEXT_2)
@printf("uncloak_file E.T. = %d s, # of decrypted bytes = %d\n", et, nclearbytes)

println("demo_cloaking: Compare newly recovered cleartext to the original cleartext .....")
cmd = `cmp $CLEARTEXT_1 $CLEARTEXT_2`
if success(cmd)
    println("demo_cloaking: Successful comparison.")
else
    println("*** demo_cloaking: FAILED comparison.")
end
println("demo_cloaking: End.")
```

Standard output:
```
demo_cloaking: Install Cloaking.jl from github .....
    Updating git-repo `https://github.com/texadactyl/Cloaking.jl`
    Updating registry at `~/.julia/registries/General`
   Resolving package versions...
  No Changes to `~/.julia/environments/v1.6/Project.toml`
  No Changes to `~/.julia/environments/v1.6/Manifest.toml`
demo_cloaking: Installation completed.
demo_cloaking: Cloaking .....
cloak_file E.T. = 0 s, # of encrypted bytes = 70496
demo_cloaking: Uncloaking .....
uncloak_file E.T. = 0 s, # of decrypted bytes = 70496
demo_cloaking: Compare newly recovered cleartext to the original cleartext .....
demo_cloaking: Successful comparison.
demo_cloaking: End.
```

#### CIPHERTEXT FILE ANATOMY

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
