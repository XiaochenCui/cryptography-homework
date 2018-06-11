import binascii
from Crypto.Hash import SHA256


def file_block_generator(content):
    block_count, reminder = divmod(len(content), 1024)
    for block_index in range(block_count + 1)[::-1]:
        start = block_index * 1024
        end = 1024 * (block_index + 1)
        if end > len(content):
            end = len(content)
        block = content[start:end]
        yield block


def blocked_hash(content):
    """

    :rtype: bytes
    """
    h = None
    for block in file_block_generator(content):
        if h:
            block = block + h
        h = SHA256.new()
        h.update(block)
        h = h.digest()
    return h


if __name__ == '__main__':
    import sys
    f = open(sys.argv[1], 'rb')
    h = blocked_hash(f.read())
    print(binascii.hexlify(h))
