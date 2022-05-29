# AES-256 encryption in GCM-mode  with PBKDF2 key derivation using hash algorithm HmacSha256

This app is demonstrating the encryption of strings or byte arrays using the **AES algorithm**.

The mode is **GCM** as it provides a built-in tag that checks for any altering of the ciphertext.

The 32 bytes long encryption key is derived from a passphrase using the **PBKDF2 algorithm** ("Password based key derivation function").

The hashing algorithm is **HmacSha256** that is available on Android SDK 26+. As this app is designed for 
SDK >= 23 I provide a PBKDF2 class that is used if the Android device is running on SDK's 23 - 25.

I have fixed the PBKDF2 iterations to 10000 - a higher value would be better but that could lengthen the key derivation on older devices.

To avoid an UI blocking the en- and decryption are running in different threads.

The passphrase could be of any length but you should define a minimum length AND some additional passphrase rules (like using number, lowercase and capital letters and special characters).

**App facts:** The app was generated on Android Studio Chipmunk 2021.2.1 with Build #AI-212.5712.43.2112.8512546,
built on April 28, 2022. Runtime version: 11.0.12+0-b1504.28-7817840 aarch64, VM: OpenJDK 64-Bit Server.
The app is compiled on Android SDK 32 ("12") and is runnable on Android SDK 23+.
