# libevent_cyassl

## description
  The project implements non-blocking cyassl connection module based on libevent, which will 
help set up a secure ssl conntion much more easily. Besides, it's take up less space than 
openssl, which makes it reasonable for embed system.

## dependencies
1. libevent V2
2. libcyassl V3.3

## reference
  Before you make use of this project, please make sure you are family with libevent, which 
will be very helpful to understand it's mechanism.

  The liblevent_cyassl is similar to libevent_openssl, providing APIs to set up ssl connection.

## samples
  Please refer to src/demo, which provides an example of how to use libevent_cyassl to set up
a ssl connection

## TODO
  I'll implement a connection module that provides the unified API to set up general socket connections, 
and ssl connections based on libevent_openssl or libevent_cyassl, which will simplify your code greatly for 
network programming.
