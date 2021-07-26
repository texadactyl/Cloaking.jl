#=
Definition file for the cloaking module.
=#

using Random


const SIZE_HMAC = 64 # Bytearray size of an HMAC
const SIZE_SALT = 8 # Bytearray size of Salt
const CHUNK_SIZE_MODULUS = 16 # Modulus for checking ciphertext chunk size (must = 0)
const MAX_CHUNK_SIZE_DEFAULT = 65536 # default read/write maximum byte size
const PAD = UInt8(0xff) # pad character for short blocks
const BOUNDARY = UInt8.(['B', 'O', 'U', 'N', 'D', 'A', 'R', 'Y'])
const CRYPTO_METHOD = "AES256" # AES 256-bit key
const HMAC_METHOD = "sha512" # SHA 512


const TIFF_PREFIX = UInt8.([
    0x4d, 0x4d, 0x00, 0x2a, # TIFF Big Endian format
    0x00, 0x00, 0x00, 0x08, # Offset of the first IFD
    0x00, 0x08,             # There are 8 IFD entries (Tag)
    0x01, 0x00,             # Tag=ImageWidth (256)
    0x00, 0x04,                 #    Type=unsigned long
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x00, 0x00, 0x20,     #    Value=32
    0x01, 0x01,             # Tag=ImageLength (257)
    0x00, 0x04,                 #    Type=unsigned long
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x00, 0x00, 0x01,     #    Value=1
    0x01, 0x02,             # Tag=BitsPerSample (258)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x08, 0xff, 0xff,     #    Value=8
    0x01, 0x03,             # Tag=ImageCompression (259)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x01, 0xff, 0xff,     #    Value=1 (none)
    0x01, 0x06,             # Tag=PhotometricInterpretation (262)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x01, 0xff, 0xff,     #    Value=1 (BlackIsZero)
    0x01, 0x11,             # Tag=StripOffsets (273)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x6e, 0xff, 0xff,     #    Value=110 (offset to start of strip)
    0x01, 0x16,             # Tag=RowsPerStrip (278)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x01, 0xff, 0xff,     #    Value=1 (1 row per strip)
    0x01, 0x17,             # Tag=StripByteCounts (279)
    0x00, 0x03,                 #    Type=unsigned short
    0x00, 0x00, 0x00, 0x01,     #    Count=1
    0x00, 0x20, 0xff, 0xff,     #    Value=32 (same as ImageWidth)
    0x00, 0x00, 0x00, 0x00, # Offset to next IFD (none)
    0x4d, 0x4d              # 2 bytes of pad up to 7*16=112 bytes
])


#=
Shamelessly cloned and hacked from JuliaIO/HexEdit.jl on github.
Date: 2021-07-24.
=#


#----------
# Display data in hex & ascii formats.
#----------
function _dump_line(offset::Integer, line::Array{UInt8})
    llen = length(line)
    plen = llen % 16

    print("$(uppercase(string(offset, base=16, pad=8))) | ")
    n = 0
    for byte = line
        # space every 4 bytes
        if n % 4 == 0
            print("  ")
        end
        print("$(uppercase(string(byte, base=16, pad=2))) ")
        n = n + 1
    end
    # line up ascii on the last line of dumps
    if plen != 0
        while n < 16
            if n % 4 == 0
                print("  ")
            end
            print("   ")
            n = n + 1
        end
    end
    print("  ")
    # print ascii
    n = 0
    for byte = line
        if byte < 32 || byte > 126
            print(".")
        else
            print(Char(byte))
        end
        n = n + 1
    end
    print("\n")
end # function dump_line


#----------
# Iterate buffer and displays data
# by tasking helper dump_line
#----------
function dump_buffer(label::String, buffer::Array{UInt8})
    @printf("%s (%d bytes)\n", label, sizeof(buffer))
    blen = length(buffer)
    llen = 16
    idx  = 1
    offset = 0
    while idx< blen
        if idx+ 16 > blen
            llen = blen - idx + 1
        end
        _dump_line(offset, buffer[idx:idx+ llen - 1])
        idx = idx + llen
        offset += llen
    end
end # function dump_buffer


#----------
# Dump an integer.
#----------
function dump_integer(label::String, arg_integer::Integer; net_order=true)
    buffer = digits(UInt8, arg_integer, base=256, pad=sizeof(arg_integer))
    if net_order
        reverse!(buffer)
    end
    dump_buffer(label, buffer)
end # function dump_integer


function pad_situation(arg::Integer)
    if arg % CHUNK_SIZE_MODULUS != 0
        return true
    end
    return false
end


function bytes2int64(arg::Vector{UInt8}; net_input=true)
    hex = bytes2hex(arg)
    return parse(Int64, hex, base=16)
end


function to_bytes(arg::Integer; net_input=false, len=sizeof(arg))
    bytes = Array{UInt8}(undef, len)
    for byte in (net_input ? (1:len) : reverse(1:len))
       bytes[byte] = arg & 0xff
       arg >>= 8
    end
    return bytes
end
