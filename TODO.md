### NEED TO DO

- SHA-3-256 and SHA-3-512 hashes user-specified file.
- SHAKE-128 and SHAKE-256 MACs user-specified length, file, passpharse.
- Encrypt user-specified data file symmetrically using a user-supplied passphrase.
  - Use the SHAKE-128 hash of the pass phrase for the symmetric key.
  - Sample a random 128-bit nonce, then use SHAKE-128 as a stream cipher by hashing the nonce and the data file
- Decrypt the symmetric cryptogram created by the encryption process mentioned under the user-supplied passphrase.

### BONUS

- Compute SHA-3-224 and SHA-3-384.
- Compute SHAKE-128 and SHAKE-256 MACs as text input directly through the APP (not read by file) under a user passphrase.
- Verify the MAC from the cryptogram computed as per the encryption bonus.
