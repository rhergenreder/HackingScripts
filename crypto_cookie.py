import base64
import hashlib
import hmac
import json
import os
import re
import urllib.parse
from Crypto.Cipher import AES

def unpad(data):
    if not data:
        return data
    last_byte = data[-1]
    if last_byte < AES.block_size:
        data = data[0:-last_byte]
    return data

def pad(data):
    if not data:
        return data
    padding = AES.block_size - (len(data) % AES.block_size)
    if padding < AES.block_size:
        data = data + bytes([padding]) * padding
    return data

def generate_mac(APP_KEY, iv, data):
    return hmac.new(key=APP_KEY, msg=base64.b64encode(iv)+base64.b64encode(data), digestmod=hashlib.sha256)

def decrypt_cookie(APP_KEY, cookie):
    json_obj = json.loads(base64.b64decode(urllib.parse.unquote(cookie)).decode())
    iv = base64.b64decode(json_obj["iv"].encode())
    encrypted = base64.b64decode(json_obj["value"].encode())
    mac = generate_mac(APP_KEY, iv, encrypted)
    if mac.hexdigest() != json_obj["mac"]:
        print("[~] WARN: macs are not equal")

    cipher = AES.new(APP_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted)).decode()

def create_cookie(APP_KEY, data):
    iv = os.urandom(AES.block_size)
    cipher = AES.new(APP_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(json.dumps(data).encode()))
    mac = generate_mac(APP_KEY, iv, encrypted)

    json_obj = {
        "iv": base64.b64encode(iv).decode(),
        "value": base64.b64encode(encrypted).decode(),
        "mac": mac.hexdigest()
    }

    new_cookie = base64.b64encode(json.dumps(json_obj).encode()).decode()
    # new_cookie = urllib.parse.quote(new_cookie)
    return new_cookie

def hkdf_extract(salt, input_key_material, hash_name='sha256'):
    """
    Extract a pseudorandom key from the input key material and salt using HMAC.

    :param salt: The salt (bytes).
    :param input_key_material: The input key material (bytes).
    :param hash_name: The hash function to use (string).
    :return: The pseudorandom key (bytes).
    """
    if salt is None or len(salt) == 0:
        salt = b'\x00' * hashlib.new(hash_name).digest_size

    return hmac.new(salt, input_key_material, hash_name).digest()

def hkdf_expand(pseudorandom_key, info=b'', length=32, hash_name='sha256'):
    """
    Expand the pseudorandom key into one or more keys using HMAC.

    :param pseudorandom_key: The pseudorandom key (bytes).
    :param info: Optional context and application-specific information (bytes).
    :param length: The length of the output key material in bytes (int).
    :param hash_name: The hash function to use (string).
    :return: The output key material (bytes).
    """
    hash_len = hashlib.new(hash_name).digest_size
    blocks_needed = (length + hash_len - 1) // hash_len
    okm = b''
    output_block = b''

    for counter in range(blocks_needed):
        output_block = hmac.new(pseudorandom_key, output_block + info + bytes([counter + 1]), hash_name).digest()
        okm += output_block

    return okm[:length]

def hkdf(input_key_material, salt, info=b'', length=32, hash_name='sha256'):
    """
    Derive keys using HKDF (extract and expand stages).

    :param input_key_material: The input key material (bytes).
    :param salt: The salt (bytes).
    :param info: Optional context and application-specific information (bytes).
    :param length: The length of the output key material in bytes (int).
    :param hash_name: The hash function to use (string).
    :return: The derived key (bytes).
    """
    pseudorandom_key = hkdf_extract(salt, input_key_material, hash_name)
    return hkdf_expand(pseudorandom_key, info, length, hash_name)

def decrypt_cookie_prestashop(COOKIE_KEY, cookie):
    assert re.match(r"^[a-fA-F0-9]+$", COOKIE_KEY)
    assert re.match(r"^[a-fA-F0-9]+$", cookie)

    # https://github.com/defuse/php-encryption/blob/master/src/Key.php
    KEY_CURRENT_VERSION = b"\xDE\xF0\x00\x00"
    HEADER_SIZE = len(KEY_CURRENT_VERSION)
    KEY_BYTE_SIZE = 32
    CHECKSUM_BYTE_SIZE = 32
    COOKIE_KEY = bytearray.fromhex(COOKIE_KEY)
    assert COOKIE_KEY.startswith(KEY_CURRENT_VERSION)
    assert len(COOKIE_KEY) == HEADER_SIZE + KEY_BYTE_SIZE + CHECKSUM_BYTE_SIZE
    real_cookie_key = COOKIE_KEY[HEADER_SIZE:HEADER_SIZE+KEY_BYTE_SIZE]
    cookie_signature_check = COOKIE_KEY[0:HEADER_SIZE+KEY_BYTE_SIZE]
    key_signature = COOKIE_KEY[HEADER_SIZE+KEY_BYTE_SIZE:]
    assert hashlib.sha256(cookie_signature_check).digest() == key_signature

    # https://github.com/defuse/php-encryption/blob/master/src/Core.php
    CURRENT_VERSION = b"\xDE\xF5\x02\x00"
    HEADER_SIZE = len(CURRENT_VERSION)
    SALT_SIZE = 32
    IV_SIZE = 16
    HMAC_SIZE = 32
    cookie = bytearray.fromhex(cookie)
    assert cookie.startswith(CURRENT_VERSION)
    assert len(cookie) >= HEADER_SIZE + SALT_SIZE + IV_SIZE + HMAC_SIZE
    salt = cookie[HEADER_SIZE:HEADER_SIZE+SALT_SIZE]
    iv = cookie[HEADER_SIZE+SALT_SIZE:HEADER_SIZE+SALT_SIZE+IV_SIZE]
    ct = cookie[HEADER_SIZE+SALT_SIZE+IV_SIZE:-HMAC_SIZE]
    hmac_data = cookie[-HMAC_SIZE:]

    PBKDF2_ITERATIONS = 100000
    ENCRYPTION_INFO_STRING = b'DefusePHP|V2|KeyForEncryption'
    AUTHENTICATION_INFO_STRING = b'DefusePHP|V2|KeyForAuthentication'

    derived_key = hkdf(real_cookie_key, salt, ENCRYPTION_INFO_STRING, 32, "sha256")

    cipher = AES.new(derived_key, AES.MODE_CTR, initial_value=iv, nonce=b"")
    plaintext = cipher.decrypt(ct).decode()

    # TODO: check hmac_data

    lines = plaintext.split("¤")
    return dict(map(lambda line: line.split("|"), lines))
