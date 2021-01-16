# crypt

This C++17 library strives to be a very small and easy to use crypto library.


## Usage example

**TBD**


## Command Line Client

This project ships also a small command line client: `crypt`:

```bash
crypt --help
Usage: crypt [OPTION...] ALGORITHM [FILE]
crypt -- a cryptography command line client.

ALGORITHM is one of the list of known algorithms. Type --list to get the list
of known algorithms supported. If FILE is ommited then stdin is read. If more
than one FILE is processed, than the output is multilined and hex.

Note also, that depending on the algorithm the input and therefore the output
may be padded to fitinto an algorithm block size definition.OPTIONS:

      --explain              Explain an algorithm.
  -h, --hex                  Output has hexadeciaml ASCII character string.
      --list                 List all known algorithms.
      --multiline            Forces multiline output.
  -?, --help                 Give this help list
      --usage                Give a short usage message
      --version              Show version.
```

The tool applies the given algorithm of the input data either as files or via stdin:

```bash
$ ls *.txt
bar.txt  foo.txt
$ cat foo.txt 
This is the foo file.
$ cat bar.txt 
... and this is the bar file.
$ cat foo.txt | crypt --hex ltc-sha256
12fdff34fa1ff51a9aa7af1878f5c4fc0a9911528ce559930da04dece88c68ce
$ crypt --hex ltc-md5 *.txt
bar.txt: 527828bb40ef39d3f88041e432761220
foo.txt: 0b05785be4e6b154c50c8654a851f1e8
```

To see which algorithms are supported issue the `--list` option:

```bash
$ crypt --list
Symmetric Ciphers
    ...
    openssl-aes-128-cbc-decryptor
    openssl-aes-128-cbc-encryptor
    openssl-aes-128-ecb-decryptor
    openssl-aes-128-ecb-encryptor
    ...

Hashes
    ltc-md5
    ltc-ripemd128
    ltc-ripemd160
    ltc-ripemd256
    ltc-ripemd320
    ltc-sha1
    ...
```

And let them have explained to you:

```bash
$ crypt --explain openssl-aes-128-cbc-encryptor
Name: openssl-aes-128-cbc-encryptor
Family: Symmetric Ciphers
Brief: OpenSSL AES 128 in CBC mode (encryptor part).
Description: This is the Advanced Encryption Standard AES (also known as Rijndael) 128 Bit encryption algorithm in CBC (cipher block chaining) mode. See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard and https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC).
Provided by: OpenSSL 1.1.1f  31 Mar 2020
Size of each input block per round: 16 Bytes
Size of each output block per round: 16 Bytes
Default input padding strategy: PKCS#5, PKCS#7
Size of final result: n/a
Initialzing arguments:
    Name: iv
        Description: An initialization vector.
        Size: 16 Bytes
        Padding strategy: PKCS#5, PKCS#7
        Mandatory: yes
    Name: key
        Description: A secret shared key.
        Size: 16 Bytes
        Padding strategy: PKCS#5, PKCS#7
        Mandatory: yes
Finalizing arguments: n/a
```


## Project layout

```
.
├── 3rd                         3rd party libraries needed (likely as git submodules).
├── cmake                       CMake additional files.
├── include                     Public header files. Add the path to this folder to your C++ search path.
│   └── headcode                
│       └── crypt               Include this: <headcode/crypt/crypt.hpp>
├── src                         Main sources.
│   ├── bin                     Binary "crypt" sources, the command line client.
│   └── lib                     Static libhcs-crypt.a sources.
├── test                        Tests.
│   ├── benchmark               Benchmark tests.
│   ├── shared                  Shared test data files.
│   └── unit                    Unit tests.
├── tools                       Various tools for run-time or build-time.
│   ├── docker                  Docker builder image definitions: Dockerfiles for various platforms to build.
│   └── package                 Package related files.
├── Changes.md                  Changes file.
├── CMakeLists.txt              The overall CMakeLists.txt.
├── Doxyfile                    Doxgen API documentation configuration.
├── LICENSE.txt                 The software license.
└── README.md                   This file.
```

## Build

### Dependencies

- cmake
- gcc (with g++) or clang (witch clang++)
- git
- make
- doxygen (with graphviz)
- [googletest](https://github.com/google/googletest) (as submodule)
- [hcs-mem](https://gitlab.com/headcode.space/memtool.git) (as submodule)
- [hcs-benchmark](https://gitlab.com/headcode.space/benchmark.git) (as submodule)

When cloning this project execute the following to clone submodules as well:

```bash
$ git submodule init
$ git submodule update
```

or simply clone with the `--recurse-submodule` option:
```bash
$ git clone --recurse-submodules
```

#### Native build

crypt is a [cmake](https://cmake.org) project with out-of-source builds in
a dedicated folder, usually labeled "build".

```bash
$ mkdir build && cd build
$ cmake ..
$ make
```

## Test

After compilation run ctest
```bash
$ cd build
$ ctest
```
Or
```bash
$ cd build
$ make test
```

_Note: Please check the test files for documentation. 
The tests are easy to read and tell you how the code is intended to be used._ 

### Test Coverage

You may also run in-deep test coverage profiling. For this, you have to turn on profiling mode:
```bash
$ cd build
$ cmake -D PROFILING_MODE_ENABLED=on ..
```

Then compile as usual and run the tests. After the tests make the `run-gcovr` target: 
```bash
$ make test
$ make run-gcovr
```

This will give you the test coverage on stdout as well as:
* `gcovr-coverage.info`:  this is the coverage info file created by gcovr
* `gcovr-report.xml`: this is the gcovr report file in xml
* `coverge-html`: this is the folder in which detailed html info of collected coverage resides
  (open up the file `coverage-html/index.html` in a browser of your choice)

in the build folder.


## Installable package creation

This project supports the creation of `DEB` and `RPM` files. This is done by specifying
the `CPACK_GENERATOR` while configuring the project.

To create an installable `DEB`:
```bash
$ cd build
$ cmake -D CMAKE_BUILD_TYPE=Release -D CPACK_GENERATOR=DEB ..
...
$ make
...
$ make package
```

To create an installable `RPM`:
```bash
$ cd build
$ cmake -D CMAKE_BUILD_TYPE=Release -D CPACK_GENERATOR=RPM ..
...
$ make
...
$ make package
```


## Notable guidelines

* Coding Guidelines: https://google.github.io/styleguide/cppguide.html
* How (not) to write git commit messages: https://www.codelord.net/2015/03/16/bad-commit-messages-hall-of-shame/
* How to version your software: https://semver.org/
* How to write a clever "Changes" file: https://keepachangelog.com/en/1.0.0/
* Folder Convention: https://github.com/KriaSoft/Folder-Structure-Conventions

---

Copyright (C) 2020-2021 headcode.space e.U.  
Oliver Maurhart <info@headcode.space>  
[https://headcode.space](https://www.headcode.space)  
