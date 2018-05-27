"""Cipher-Block Chaining encrypt/decrypt"""
import binascii
from Crypto.Cipher import AES
from cxc_toolkit.bytes import xor


def msg_block_generator(msg, padding=False):
    while len(msg) >= 16:
        yield msg[:16]
        msg = msg[16:]
    if len(msg) > 0:
        if not padding:
            yield msg
            return

        reminder = 16 - len(msg)
        msg = msg + bytes([reminder]) * reminder
        yield msg
    else:
        yield b'16' * 16


def cipher_block_generator(cipher):
    while len(cipher):
        yield cipher[:16]
        cipher = cipher[16:]


def encrypt(msg, key, iv):
    """
    :type msg: bytes
    :type key: bytes
    :type iv: bytes
    :rtype: bytes
    """
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_block = iv
    ciphertext = iv
    for msg_block in msg_block_generator(msg, padding=True):
        cipher_block = cipher.encrypt(xor(cipher_block, msg_block))
        ciphertext += cipher_block
    return ciphertext


def decrypt(cipher_text, key):
    """
    :type cipher_text: bytes
    :type key: bytes
    :rtype: bytes
    """
    cipher = AES.new(key, AES.MODE_ECB)
    iv, cipher_text = cipher_text[:16], cipher_text[16:]
    msg = b''
    for cipher_block in cipher_block_generator(cipher_text):
        msg_block = xor(cipher.decrypt(cipher_block), iv)
        iv = cipher_block
        msg += msg_block
    if msg[-16:] == b'\x16' * 16:
        return msg[:-16]
    pad_bytes = msg[-1]
    reminder = len(msg) - pad_bytes
    if msg[reminder:] == bytes([pad_bytes]) * pad_bytes:
        return msg[:reminder]
    else:
        print('Cipher_text is invalid')


if __name__ == '__main__':
    key = binascii.unhexlify('140b41b22a29beb4061bda66b6747e14')
    cipher_text = binascii.unhexlify('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
    print(decrypt(cipher_text, key))

    iv = binascii.unhexlify('4ca00ff4c898d61e1edbf1800618fb28')
    msg = b'Basic CBC mode encryption needs padding.'
    print(binascii.hexlify(encrypt(msg, key, iv)))

    key = binascii.unhexlify('140b41b22a29beb4061bda66b6747e14')
    cipher_text = binascii.unhexlify('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')
    print(decrypt(cipher_text, key))
