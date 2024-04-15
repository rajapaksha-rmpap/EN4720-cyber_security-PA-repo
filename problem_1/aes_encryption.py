import os
import base64
from cryptography.fernet import Fernet

def encrypt_phrase(phrase):
  
  # Generate a random key using Fernet.
  key = Fernet.generate_key()

  # Create a Fernet object with the key.
  f = Fernet(key)

  # Encrypt the phrase, while enconding using the utf-8 character set. 
  phrase = phrase.encode("utf-8")
  encrypted_phrase = f.encrypt(phrase)

  # Return the encrypted phrase and key.
  return encrypted_phrase, key


if __name__ == "__main__":

  # Get the phrase to encrypt from the user.
  phrase = input("Enter the phrase to encrypt: ")

  # Encrypt the phrase, calling the encryption function.
  encrypted_phrase, key = encrypt_phrase(phrase)

  # Print the encrypted phrase and key
  print(f"phrase     : {phrase}")
  print(f"key        : {key}")
  print(f"ciphertext : {encrypted_phrase}")
