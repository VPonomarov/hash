
INT_BITS = 32

def to_bits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def from_bits(bits):
    chars = []
    for b in range(int(len(bits) / 8)):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

def left_rotate(n, d):
    return ((n << d)|(n >> (INT_BITS - d))) & 0xffffffff

# SHA-1
def sha1(message):
    # Pad message
    padded_message = to_bits(message)
    l = len(padded_message)
    padded_message.append(1)

    k = 512 - (l + 1 + 2 * INT_BITS) % 512
    l_bin = bin(l)[2:]
    padded_message.extend([0] * (k + 2 * INT_BITS - len(l_bin)))
    padded_message.extend(l_bin)
    
    # Parse message
    m = []
    for i in range(int(len(padded_message) / 512)):
        m.append(padded_message[i * 512 : (i + 1) * 512])

    # Set initial values
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0 

    # Compute hash
    for chunk_idx in range(len(m)):
        # Prepare words
        w = []
        for t in range(16):
            w.append(int("".join([str(b) for b in m[chunk_idx][t * INT_BITS : (t + 1) * INT_BITS]]), 2))

        for t in range(16, 80):
            w.append(left_rotate(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1))
        
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for t in range(0, 80):
            if (t < 20):
                f = (b & c) | (~b & d)
                # f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif (t < 40):
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif (t < 60):
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            tmp = (left_rotate(a, 5) + f + e + k + w[t]) & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30) 
            b = a
            a = tmp

            # print("t = ", t, ": ", "a = {:08x}".format(a), "b = {:08x}".format(b), "c = {:08x}".format(c), "d = {:08x}".format(d), "e = {:08x}".format(e))

        # Updated values
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return (h0 << 128)|(h1 << 96)|(h2 << 64)|(h3 << 32)|(h4)

print("{:x}".format(sha1("abc")))
print("{:x}".format(sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))
print("{:x}".format(sha1("a" * 1000000)))
