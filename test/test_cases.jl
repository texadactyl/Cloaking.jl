using Printf
using Cloaking


function do_case(id::Integer, cleartext::AbstractString, password::AbstractString; outdir="./test_data/", debugging=false)
    @printf("\n=== Text Case %03d ====\n", id)
    filename = basename(cleartext)
    ix = findlast(isequal('.'), filename)
    if ix == nothing
        filestem = filename
    else
        filestem = filename[1 : ix - 1]
    end
    outdir = abspath(outdir)
    encfile = joinpath(outdir, string(filestem, ".enc"))
    decfile = joinpath(outdir, string(filestem, ".dec"))
    et, ncipherbytes = cloak_file(password, cleartext, encfile, debugging=debugging)
    et, nclearbytes = uncloak_file(password, encfile, decfile, debugging=debugging)

    @printf("one_case: cloak   --> %s, E.T. = %d s, # of encrypted bytes = %d\n", encfile, et, ncipherbytes)
    @printf("one_case: uncloak --> %s, E.T. = %d s, # of decrypted bytes = %d\n", decfile, et, nclearbytes)

    cmd = `cmp $cleartext $decfile`
    if success(cmd)
        println("\nSuccessful comparison")
    else
        println("\n*** FAILED comparison")
    end
end


datadir = string(@__DIR__, "/test_data/")
secretfile = string(datadir, "the_secret_sauce.txt")
password = open(secretfile) do file
    read(file, String)
end

do_case(1, string(datadir, "mary_1120.txt"), password)
do_case(2, string(datadir, "mary_1121.txt"), password)
do_case(3, string(datadir, "123.txt"), password)
do_case(4, "/boot/initrd.img", password)


