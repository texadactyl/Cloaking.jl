#=
Simple Cloaking test.
=#

using Printf
include("cloak_file.jl")
include("uncloak_file.jl")

DIR = "/home/elkins/BASIS/julia/Cloaking.jl/"

SECRET = string(DIR, "test/test_data/the_secret_sauce.txt")
DEBUGGING = true

CLEARTEXT_1 = "/boot/initrd.img"
CLEARTEXT_1 = string(DIR, "test/test_data/123.txt")
CLEARTEXT_1 = string(DIR, "test/test_data/mary.txt")
CIPHERTEXT = string(DIR, "test/test_data/ciphertext_1.tiff")
CLEARTEXT_2 = string(DIR, "test/test_data/cleartext_2.txt")

password = open(SECRET) do file
    read(file, String)
end

println("===============================================================")
et, ncipherbytes = cloak_file(password, CLEARTEXT_1, CIPHERTEXT, debugging=DEBUGGING)
println("===============================================================")
et, nclearbytes = uncloak_file(password, CIPHERTEXT, CLEARTEXT_2, debugging=DEBUGGING)
println("===============================================================")

@printf("E.T. = %d s, # of encrypted bytes = %d\n", et, ncipherbytes)
@printf("E.T. = %d s, # of decrypted bytes = %d\n", et, nclearbytes)

cmd = `cmp $CLEARTEXT_1 $CLEARTEXT_2`
if success(cmd)
    println("\nSuccessful comparison")
else
    println("\n*** FAILED comparison")
end
