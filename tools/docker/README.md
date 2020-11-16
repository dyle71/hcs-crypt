# Docker Containers

This folder contains necessary items to create Docker containers for building the project.


## Prerequisite

Install a docker runtime on your host system.


## Builders

Builders are Docker containers which are capable to build the software and create
installable package artefacts. All builder Dockerfiles are labeled `Dockerfile.build.*`.

1. Create a Docker builder for a chosen platform (e.g. Debian 10 - "Buster") in the current folder:
```bash
$ docker build --tag hcs-crypt:debian-buster --file Dockerfile.build.debian-buster .
```


2. Launch a builder
```bash
$ docker run -it -d --rm --name hcs-crypt_debian-buster hcs-crypt:debian-buster
```
This will run have the Docker builder run in the background.


3. Create the binary and packages inside the container


3.1 Create and test a Debug version and a source tarball:

```bash
$ docker exec -it hcs-crypt_debian-buster git clone https://gitlab.com/headcode.space/crypt.git . 
...
$ docker exec -it hcs-crypt_debian-buster /bin/bash
root@45bbb4fd3758:/build# mkdir build &> /dev/null
root@45bbb4fd3758:/build# cd build
root@45bbb4fd3758:/build# cmake -D CMAKE_BUILD_TYPE="Debug" ..
..
root@45bbb4fd3758:/build# make && make test && make package
```

If successful this will create a tarball (`.tar.gz`) inside the build folder.


3.2 Create and package Release version:
```bash
$ docker exec -it hcs-crypt_debian-buster git clone https://gitlab.com/headcode.space/crypt.git . 
...
$ docker exec -it hcs-crypt_debian-buster /bin/bash
root@45bbb4fd3758:/build# mkdir build &> /dev/null
root@45bbb4fd3758:/build# cd build
root@45bbb4fd3758:/build# cmake -D CMAKE_BUILD_TYPE="Release" -D CPACK_GENERATOR="DEB" ..
..
root@45bbb4fd3758:/build# make && make package
```

If successful this will create a Debian package (`.deb`) inside the build folder.
If you want to create RPM packages instead, issue a `-D CPACK_GENERATOR="RPM"` instead:
```
root@45bbb4fd3758:/build# cmake -D CMAKE_BUILD_TYPE="Release" -D CPACK_GENERATOR="RPM" ..
``` 


4. Stop the Builder

The Builder container will remain running in the background until stopped, e.g.:
```bash
$ docker stop hcs-crypt_debian-buster 
```


---

Oliver Maurhart, <oliver.maurhart@headcode.space>
(C)opyright 2020 headcode.space
[https://headcode.space](https://www.headcode.space)

