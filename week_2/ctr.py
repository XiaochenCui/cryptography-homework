"""CounTer Mode encrypt/decrypt"""
import binascii
from Crypto.Cipher import AES
from cxc_toolkit import byte, integer

from week_2.cbc import msg_block_generator, cipher_block_generator


def encrypt(msg, key, iv):
    """
    :type msg: bytes
    :type key: bytes
    :type iv: bytes
    :rtype: bytes
    """
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b''
    for i, msg_block in enumerate(msg_block_generator(msg, padding=False)):
        cipher_block = cipher.encrypt(byte.add(iv, i))
        cipher_block = byte.xor(msg_block, cipher_block)
        ciphertext += cipher_block
    return ciphertext


def decrypt(cipher_text, key):
    """
    :type cipher_text: bytes
    :type key: bytes
    :rtype: bytes
    """
    iv, cipher_text = cipher_text[:16], cipher_text[16:]
    cipher = AES.new(key, AES.MODE_ECB)
    msg = b''
    for i, cipher_block in enumerate(cipher_block_generator(cipher_text)):
        iv_encrypted = cipher.encrypt(byte.add(iv, i))
        msg_block = byte.xor(cipher_block, iv_encrypted)
        msg += msg_block
    return msg


if __name__ == '__main__':
    key = binascii.unhexlify('36f18357be4dbd77f050515c73fcf9f2')
    cipher_text = binascii.unhexlify('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
    print(decrypt(cipher_text, key))

    iv = binascii.unhexlify('69dda8455c7dd4254bf353b773304eec')
    msg = b'CTR mode lets you build a stream cipher from a block cipher.'
    print(binascii.hexlify(encrypt(msg, key, iv)))

    key = binascii.unhexlify('36f18357be4dbd77f050515c73fcf9f2')
    cipher_text = binascii.unhexlify('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')
    print(decrypt(cipher_text, key))
