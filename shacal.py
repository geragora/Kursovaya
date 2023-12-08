import secrets
import struct

K0 = 0x5A827999
K1 = 0x6ED9EBA1
K2 = 0x8F1BBCDC
K3 = 0xCA62C1D6
ROUNDS = 80
WORDS_PER_KEY = 16
WORDS_PER_BLOCK = 5


def rotate_left(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def f0(B, C, D):
    return (B & C) | ((~B) & D)


def f1(B, C, D):
    return B ^ C ^ D


def f2(B, C, D):
    return (B & C) | (B & D) | (C & D)


def f3(B, C, D):
    return B ^ C ^ D


def initialise_key(initial_key):
    expanded_key = list(initial_key)

    while len(expanded_key) < ROUNDS:
        expanded_key.extend(initial_key)

    for t in range(WORDS_PER_KEY, ROUNDS):
        expanded_key.append(rotate_left(
            expanded_key[t - 3] ^ expanded_key[t - 8] ^ expanded_key[t - 14] ^ expanded_key[t - 16], 1))

    for t in range(20):
        expanded_key[t] += K0
    for t in range(20, 40):
        expanded_key[t] += K1
    for t in range(40, 60):
        expanded_key[t] += K2
    for t in range(60, 80):
        expanded_key[t] += K3

    return expanded_key


def encryption_round(block, round_function):
    A, B, C, D, E = block
    tmp = round_function(B, C, D)
    tmp = (tmp + E + rotate_left(A, 5)) & 0xFFFFFFFF
    block[4] = D
    block[3] = C
    block[2] = rotate_left(B, 30)
    block[1] = A
    block[0] = tmp


def decryption_round(block, round_function):
    A, B, C, D, E = block
    tmp = round_function(rotate_left(C, 2), D, E)
    tmp = (A - tmp - rotate_left(B, 5)) & 0xFFFFFFFF
    block[0] = B
    block[1] = rotate_left(C, 2)
    block[2] = D
    block[3] = E
    block[4] = tmp


def key_add(block, round_key):
    block[0] = (block[0] + round_key) & 0xFFFFFFFF


def encrypt(key, block):
    t = 0
    for t in range(20):
        encryption_round(block, f0)
        key_add(block, key[t])

    for t in range(20, 40):
        encryption_round(block, f1)
        key_add(block, key[t])

    for t in range(40, 60):
        encryption_round(block, f2)
        key_add(block, key[t])

    for t in range(60, 80):
        encryption_round(block, f3)
        key_add(block, key[t])


def decrypt(key, block):
    t = 0
    for t in range(20):
        key_add(block, -key[80 - t - 1])
        decryption_round(block, f3)

    for t in range(20, 40):
        key_add(block, -key[80 - t - 1])
        decryption_round(block, f2)

    for t in range(40, 60):
        key_add(block, -key[80 - t - 1])
        decryption_round(block, f1)

    for t in range(60, 80):
        key_add(block, -key[80 - t - 1])
        decryption_round(block, f0)



def read_file(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
    return content

def write_file(file_path, content):
    with open(file_path, 'wb') as file:
        file.write(content)

def process_file(file_path, key, encryption=True):
    content = read_file(file_path)
    word_size = 4
    block_size = 5

    content += bytes([0] * (block_size * word_size - len(content) % (block_size * word_size)))

    blocks = [struct.unpack('>I', content[i:i + word_size])[0] for i in range(0, len(content), word_size)]

    expanded_key = initialise_key(key)
    for i in range(0, len(blocks), block_size):
        block = blocks[i:i + block_size]

        if encryption:
            encrypt(expanded_key, block)
        else:
            decrypt(expanded_key, block)
        blocks[i:i + block_size] = block

    processed_content = b''.join(struct.pack('>I', value) for value in blocks)


    return processed_content



def generate_random_key():
    return [secrets.randbits(32) for _ in range(4)]
