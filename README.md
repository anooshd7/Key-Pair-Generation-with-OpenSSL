<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project
C++ program that uses the OpenSSL library to generate a key pair, which consists of a public key and a private key for each user. It then uses Diffie-Hellman algorithm
to generate a shared secret for the first user using the first user's private key and second user's public key. It then generates a shared secret for the second user
using second user's private key and first user's public key. These shared secrets are the same, according to the Diffie-Hellman algorithm.
It then uses AES 256 Encryption to encrypt a given string, using the shared secret as the round key for encryption. It then subsequently decrypts it using AES 256 Decryption. 
Also, Base 64 encoding and decoding is used to convert the shared secret to an encryptable format.
The program outputs all the generated keys to separate files.
 
<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started
### Prerequisites
#### OpenSSl
 Install OpenSSL and add it to your path. 
 
 #### Visual Studio 2022
 Install Visual Studio 2022 and set it up. Also add the path to the OpenSSL directories in the Visual Studio project. This should include paths to libcrypto.dll and libssl.dll
 
<!-- USAGE EXAMPLES -->
## Usage
In Visual Studio 2022, build the solution for the KeyPair.cpp file and then run the program. The generated keys are printed to files which are generated in the same
directory, and the string is encrypted and decrypted.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
