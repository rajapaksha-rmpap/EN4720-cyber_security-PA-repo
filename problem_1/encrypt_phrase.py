import os
import base64
import random
from Crypto.Cipher import AES

def encrypt_phrase(phrase):
  """
  Function encrypts a phrase using AES key generated within the function.
  Inputs:
    phrase: The phrase to encrypt.
  Output:
    Encrypted phrase and the key used along with the generated initialization vector (IV).
  """

  # Generate a 16-byte random key.
  key = os.urandom(16)

  # =============== Generate a 16-byte random initialization vector (IV) ===============
  iv = os.urandom(16)
  
  # Create an AES cipher object with the generated key.
  cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

  # Encode using the utf-8 character set and add the padding to the phrase.
  phrase = phrase.encode("utf-8")
  AES_BLOCK_SIZE = 16
  padded_phrase = pad(data=phrase, block_size=AES_BLOCK_SIZE)
  
  # Encrypt the phrase.
  encrypted_phrase = cipher.encrypt(padded_phrase)

  # Encode the encrypted phrase and iv to base64
  encrypted_phrase = base64.b64encode(encrypted_phrase)
  iv = base64.b64encode(iv)
    
  # Return the output of encrypted phrase and the key.
  return encrypted_phrase, key.hex(), iv


def pad(data, block_size):
  """ 
  Function pads a string (Phrase entered by user) to a multiple of the specified block size to meet AES requirments.
  Inputs:
    data: The phrase to be pad.
    block_size: The block size to be pad to.
  Outpur:
    The padded string (Phrase).
  """

  null_byte = b'\x00' # b'0000 0000

  padding_len = 0 if len(data) % block_size == 0 else block_size - len(data) % block_size
  padding = null_byte * padding_len
  
  return data + padding


if __name__ == "__main__":
  # Get the phrase to encrypt from the user.
  phrase = input("Enter the phrase to encrypt: ")

  # Encrypt the phrase.
  cyphertext, key, iv = encrypt_phrase(phrase)

  # Print the encrypted phrase, passphrase, and the key.
  print(f"phrase       : {phrase}")
  print(f"key (in hex) : {key}")
  print(f"iv           : {iv}")
  print(f"ciphertext   : {cyphertext}")
