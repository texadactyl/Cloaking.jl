#=
Example use of Cloaking.
=#

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
