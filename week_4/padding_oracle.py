import sys
import time
import requests
import binascii
import logging.config


logging.config.fileConfig('logging_config.ini')
logger = logging.getLogger(__name__)


TARGET = 'http://crypto-class.appspot.com/po?er='


def query():
    origin_ciphertext_hex = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"

    # Get origin ciphertext
    origin_ciphertext = binascii.unhexlify(origin_ciphertext_hex)

    # Init message list to store guessed message
    message = []

    # End of the replaced pard
    end_position = len(origin_ciphertext) - 17

    # Guess for all 256 possiable
    for guess in range(256):
        replaced_number = origin_ciphertext[-17] ^ guess ^ 1

        faked_ciphertext = origin_ciphertext[:-17] + bytes([replaced_number]) + origin_ciphertext[-16:]
        faked_ciphertext_hex = binascii.hexlify(faked_ciphertext).decode()

        target = TARGET + faked_ciphertext_hex
        response = requests.get(target)
        code = response.status_code

        if code == 404:
            logger.info('Origin pad found: {}'.format(guess))
            origin_pad = guess
            break
        time.sleep(0.1)

    # position stands for current guessing position
    for position in range(0, end_position + 1)[::-1]:
        logger.info("Position: {}".format(position))
        pad = 16 - position % 16
        logger.info('Pad: {}'.format(pad))

        while end_position - position >= 16:
            end_position -= 16

        truncated_origin_ciphertext = origin_ciphertext[:end_position + 16 + 1]

        # Guess from 0 to 127
        for guess in range(128):
            replaced_number = origin_ciphertext[position] ^ guess ^ pad

            replace_part = [replaced_number]
            current_block_guessed_message_size = len(message) % 16
            for i, m in enumerate(message[:current_block_guessed_message_size], start=1):
                replace_part.append(origin_ciphertext[position + i] ^ m ^ pad)

            logger.debug('replace_part: {}'.format(replace_part))
            logger.debug('message: {}'.format(message))
            replace_part = bytes(bytearray(replace_part))

            # Generate fake ciphertext
            logger.debug('length of pre: {pre}, length of replace_part: {mid}, length of remainder: {last}'.format(
                pre=position,
                mid=len(replace_part),
                last=16,
            ))
            faked_ciphertext = origin_ciphertext[:position] + replace_part + truncated_origin_ciphertext[-16:]
            faked_ciphertext_hex = binascii.hexlify(faked_ciphertext).decode()

            # Send request to get result
            target = TARGET + faked_ciphertext_hex
            response = requests.get(target)
            code = response.status_code

            logger.info('guess: {guess}, replaced_number: {replaced_number}, code: {code}'.format(
                guess=guess,
                replaced_number=replaced_number,
                code=code,
            ))
            logger.info(faked_ciphertext_hex)

            # Message get, go to guess next message
            if code == 404:
                logger.info("Padding is valid, but the message is malformed, guess char: {}({})".format(chr(guess), guess))
                message = [guess] + message
                break

            # Get first position of origin pad
            if faked_ciphertext == origin_ciphertext and pad == origin_pad:
                message = [guess] + message
                break
            time.sleep(0.1)
        else:
            logger.info('All guesses are invalid, position {position}, pad {pad}'.format(
                position=position,
                pad=pad,
            ))
            sys.exit(1)

        message = bytes(bytearray(list(filter(lambda i: i > 16, message)))).decode()
        print('message is: {}'.format(message))


if __name__ == "__main__":
    query()
