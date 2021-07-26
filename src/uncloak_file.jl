#=
The following code provides a password-based security of a single file or
a single file system archive file (E.g. .tar.gz).
=#

using Nettle
using Printf
using Random


include("cloaking_utils.jl")


function uncloak_file(in_password,
                 in_file_path,
                 out_file_path;
                 debugging=false,
                 max_chunk_size=MAX_CHUNK_SIZE_DEFAULT)
    """
    Decrypts a file using AES (CBC mode) with
    a key produced from the given password.

    Parameters:
        in_password:
            Same description as for cloak_file.

        in_file_path:
            Path name of the input ciphertext file

        out_file_path:
            Path name of output cleartext file.

        debugging: true/false.

        max_chunk_size (optional):
            Same description as for cloak_file..

    Returns:
        Elapsed time in seconds.
        Number of data blocks processed.
    """

    # Take start time
    tstart = time()
    buffer = Vector{UInt8}(undef, max_chunk_size)
    computed_cleartext_size = 0

    open(in_file_path, "r") do infile

        open(out_file_path, "w") do outfile

            # Get input file TIFF prefix and validate it.
            observed_tiff_prefix = Vector{UInt8}(undef, sizeof(TIFF_PREFIX))
            nbytes = readbytes!(infile, observed_tiff_prefix, sizeof(TIFF_PREFIX))
            @assert nbytes == sizeof(TIFF_PREFIX) "*** uncloak_file: Input file truncated at the standard prefix!"
            if observed_tiff_prefix != TIFF_PREFIX
                dump_buffer("*** uncloak_file: observed_tiff_prefix", observed_tiff_prefix)
                throw(ErrorException("*** uncloak_file: Input file standard prefix mismatch!"))
            end

            # Get salt.  Make IV and key.
            salt = Vector{UInt8}(undef, SIZE_SALT)
            nbytes = readbytes!(infile, salt, SIZE_SALT)
            @assert nbytes == SIZE_SALT "*** uncloak_file: Input file truncated at the salt!"
            (key32, iv16) = gen_key32_iv16(Vector{UInt8}(in_password), salt)
            if debugging
                dump_buffer("uncloak_file: salt", salt)
                dump_buffer("uncloak_file: key32", key32)
                dump_buffer("uncloak_file: iv16", iv16)
            end

            # Initialise decryptor and HMAC.
            decryptor = Decryptor(CRYPTO_METHOD, key32)
            hmac = HMACState(HMAC_METHOD, key32)

            # Update accumulated HMAC with TIFF prefix and salt.
            update!(hmac, observed_tiff_prefix)
            update!(hmac, salt)

            # Get original cleartext file size.
            packed_fs = Vector{UInt8}(undef, 8)
            nbytes = readbytes!(infile, packed_fs, 8)
            if debugging
                dump_buffer("uncloak_file: original cleartext file size", packed_fs)
            end
            update!(hmac, packed_fs)
            original_file_size = bytes2int64(packed_fs)
            if debugging
                @printf("uncloak_file: original_file_size = %d\n", original_file_size)
            end

            # Get boundary.
            observed_boundary = Vector{UInt8}(undef, sizeof(BOUNDARY))
            nbytes = readbytes!(infile, observed_boundary, sizeof(BOUNDARY))
            @assert nbytes == sizeof(BOUNDARY) "*** uncloak_file: Input file truncated at the the boundary field!"
            if BOUNDARY != observed_boundary
                dump_buffer("*** uncloak_file: observed_boundary", observed_boundary)
                throw(ErrorException("*** uncloak_file: uncloak_file: Input file mismatch on the boundary!"))
            end
            update!(hmac, observed_boundary)

            # Initialize byte-countdown = original file size + pad size
            countdown = original_file_size
            if countdown % CHUNK_SIZE_MODULUS != 0
                pad_size = CHUNK_SIZE_MODULUS - (countdown % CHUNK_SIZE_MODULUS)
                countdown += pad_size
            end
            if debugging
                println("uncloak_file: Retrieved boundary ok")
                @printf("uncloak_file: Number of input data bytes to process = %d\n", countdown)
            end

            # ===== Begin main loop ============================================
            while true # forever until a break

                if debugging
                    @printf("uncloak_file: Number of input bytes left: %d\n", countdown)
                end

                # Down to the HMAC (last) chunk?
                if countdown == 0

                    # Read all of the data + pad bytes.
                    # Read the HMAC from the file.
                    expected_hmac = digest!(hmac)
                    observed_hmac = Vector{UInt8}(undef, SIZE_HMAC)
                    nbytes = readbytes!(infile, observed_hmac, SIZE_HMAC)
                    @assert nbytes == sizeof(expected_hmac) "*** uncloak_file: Input file truncated at the the HMAC field!"
                    countdown -= sizeof(expected_hmac)

                    # Validate HMAC from file.
                    if debugging
                        dump_buffer("uncloak_file: observed_hmac", observed_hmac)
                        dump_buffer("uncloak_file: expected_hmac", expected_hmac)
                    end
                    if expected_hmac != observed_hmac
                        throw(ErrorException("*** uncloak_file: uncloak_file: Input file HMAC mismatch!"))
                    end

                    # Success!  All done with input file.  Break out of read/write loop.
                    break

                end # if countdown == 0

                # Not the HMAC (final) block.  Read next file chunk.
                # If the countdown < max_chunk_size, then we found the last data block
                # before the HMAC.
                if countdown < max_chunk_size
                    read_size = countdown
                else
                    read_size = max_chunk_size
                end
                nbytes = readbytes!(infile, buffer, read_size)

                # At this point, nbytes should be = read_size.
                @assert nbytes != 0 "*** uncloak_file: Unexpected zero read length (hit EOF)!"
                @assert nbytes == read_size "*** uncloak_file: Unexpected short block from input file"

                # All is well so far.  Decrease countdown by amount just read.
                countdown -= nbytes

                # Write out decrypted block.
                ciphertext = @view buffer[1 : nbytes]
                if debugging
                    dump_buffer("uncloak_file: input ciphertext", copy(ciphertext))
                end

                # Accumulate expected value of HMAC using ciphertext input.
                update!(hmac, ciphertext)

                # Get the cleartext.
                cleartext = decrypt(decryptor, :CBC, iv16, ciphertext)
                if debugging
                    dump_buffer("uncloak_file: output cleartext", cleartext)
                end

                # Write out decrypted block.
                nbytes = write(outfile, cleartext)
                computed_cleartext_size += nbytes
                if debugging
                    @printf("uncloak_file: size of written cleartext = %d, sizeof(cleartext) = %d\n", nbytes, sizeof(cleartext))
                end

            end # while true

            truncate(outfile, original_file_size)

        end # outfile

    end # infile

    # Done.

    # Return to caller.
    return time() - tstart, computed_cleartext_size

end
