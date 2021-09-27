#=
The following code provides a password-based protection of a single file or
a single file system archive file (E.g. .tar.gz).
=#

using Nettle
using Printf
using Random


include("cloaking_utils.jl")


function cloak_file(in_password,
               in_file_path,
               out_file_path;
               debugging=false,
               max_chunk_size=MAX_CHUNK_SIZE_DEFAULT)
    #=
    Encrypts a file using AES (CBC mode) with
    a key produced from the given password.

    Parameters:
        in_password:
            This password is securely hashed to produce a 32-byte digest.
            The digest is used as the AES256 key.

        in_file_path:
            Path name of the input cleartext file

        out_file_path:
            Path name of output ciphertext file.

        debugging: true/false.

        max_chunk_size (optional):
            Sets the size of the read-file chunk which is
            used to read and encrypt the file.
            Larger chunk sizes can be faster for some files and machines.
            The max_chunk_size must be divisible by 16.
            Default value: 64k.

    Returns:
        Elapsed time in seconds
        Number of data blocks processed.
    =#

    # Take start time
    tstart = time()

    # File buffer, computed file size
    buffer = Vector{UInt8}(undef, max_chunk_size)
    computed_ciphertext_size = 0

    # Get input file size (bytes)
    original_file_size::Int64 = filesize(in_file_path) # Ensure an 8-byte integer for original_file_size.
    if debugging
        @printf("cloak_file: original_file_size = %d\n", original_file_size)
        dump_integer("cloak_file: original_file_size", original_file_size, net_order=true)
    end

    # Validate max_chunk_size
    @assert (max_chunk_size % CHUNK_SIZE_MODULUS == 0) @sprintf "*** cloak_file: max_chunk_size(%i) modulo %i must be zero!" max_chunk_size CHUNK_SIZE_MODULUS

    # Create key and salt.
    salt = rand(UInt8, SIZE_SALT)
    (key32, iv16) = gen_key32_iv16(Vector{UInt8}(in_password), salt)
    if debugging
        dump_buffer("cloak_file: key32", key32)
        dump_buffer("cloak_file: iv16", iv16)
    end

    # Initialize encryptor and HMAC
    encryptor = Encryptor(CRYPTO_METHOD, key32)
    hmac = HMACState(HMAC_METHOD, key32)

    # Start main loop.
    open(in_file_path, "r") do infile
        open(out_file_path, "w") do outfile

            # Write out TIFF prefix (112 bytes)
            if debugging
                dump_buffer("cloak_file: TIFF_PREFIX", TIFF_PREFIX)
            end
            write(outfile, TIFF_PREFIX)
            update!(hmac, TIFF_PREFIX)

            # Write out salt (8 bytes)
            if debugging
                dump_buffer("cloak_file: salt", salt)
            end
            write(outfile, salt)
            update!(hmac, salt)

            # Write out file size unsigned long long field (8 bytes)
            ofs_bytes = to_bytes(original_file_size)
            write(outfile, ofs_bytes)
            update!(hmac, ofs_bytes)

            # Write out boundary.
            if debugging
                dump_buffer("cloak_file: BOUNDARY", BOUNDARY)
            end
            write(outfile, BOUNDARY)
            update!(hmac, BOUNDARY)

            # Begin read/write loop
            while true

                nbytes = readbytes!(infile, buffer, max_chunk_size)
                if nbytes == 0
                    # Hit end of input file
                    break
                end

                # Got more input data.
                block = @view buffer[1 : nbytes]

                # Encrypt the buffer and write it out.
                if pad_situation(sizeof(block))
                    ciphertext = encrypt(encryptor,
                                            :CBC,
                                            iv16,
                                            add_padding_PKCS5(Vector{UInt8}(block), CHUNK_SIZE_MODULUS))
                else
                    ciphertext = encrypt(encryptor, :CBC, iv16, block)
                end
                write(outfile, ciphertext)
                if debugging
                    dump_buffer("cloak_file: input cleartext", copy(block))
                    if pad_situation(sizeof(block))
                        dump_buffer("cloak_file: output ciphertext (padded)", ciphertext)
                    else
                        dump_buffer("cloak_file: output ciphertext (unpadded)", ciphertext)
                    end
                end
                computed_ciphertext_size += sizeof(ciphertext)

                # Update HMAC using ciphertext output
                update!(hmac, ciphertext)

            end # while true

            # Done with read/write loop: Write out HMAC.
            final_digest = digest!(hmac)
            write(outfile, final_digest)
            if debugging
                dump_buffer("cloak_file: final_digest", final_digest)
            end

        end # outfile

    end # infile

    # Done.
    return time() - tstart, computed_ciphertext_size

end # function cloak_file
