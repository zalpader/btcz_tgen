import os
import secrets
import hashlib
import ecdsa
from datetime import datetime

NUM_ADDRESSES = 25
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
os.system("title btcz_tgen")

def base58_encode(data_bytes: bytes) -> str:
    number = int.from_bytes(data_bytes, 'big')
    encoded = ''
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    leading_ones = '1' * (len(data_bytes) - len(data_bytes.lstrip(b'\0')))
    return leading_ones + encoded

def generate_btcz_keypair() -> tuple[str, str]:
    private_key_bytes = secrets.token_bytes(32)
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    public_point = signing_key.verifying_key.pubkey.point
    prefix_byte = b'\x02' if public_point.y() % 2 == 0 else b'\x03'
    compressed_public_key = prefix_byte + public_point.x().to_bytes(32, 'big')
    sha256_hash = hashlib.sha256(compressed_public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    versioned_payload = b'\x1c\xb8' + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    address = base58_encode(versioned_payload + checksum)

    wif_payload = b'\x80' + private_key_bytes + b'\x01'
    wif_checksum = hashlib.sha256(hashlib.sha256(wif_payload).digest()).digest()[:4]
    wif_key = base58_encode(wif_payload + wif_checksum)

    return address, wif_key

filename = f'btcz_{datetime.now():%Y%m%d_%H.%M.%S}.txt'
with open(filename, 'w') as file:
    for _ in range(NUM_ADDRESSES):
        btcz_address, wif_private_key = generate_btcz_keypair()
        line = f'{btcz_address} {wif_private_key}'
        print(line)
        file.write(line + '\n')

input()
