ct-submit
=========

Introduction
------------

`ct-submit` is a program that submits X.509 certificate chains to
[Certificate Transparency][ct] log servers. It returns the Signed Certificate
Timestamp structure in a format suitable for use with Apache's
[mod\_ssl\_ct][apache] module and [nginx-ct][nginx].

Building
--------

`ct-submit` is written in [Go][go]. Just run `go build` to build it.

Usage
-----

`ct-submit` takes a single argument - the URL of the log server. If the scheme
is not specified it defaults to `https://`. It reads the certificate chain in
PEM format from `stdin`.  The leaf certificate should be the first certificate
in the chain, followed by any intermediate certificates and, optionally, the
root certificate.

The encoded SCT structure is written in binary to `stdout`.

The following example demonstrates submitting the chain in `gpe.pem` to
Google's pilot log server. The SCT is written to `gpe.sct`, which is in a format
suitable for use with Apache's mod\_ssl\_ct module and nginx-ct.

    $ ./ct-submit ct.googleapis.com/pilot <gpe.pem >gpe.sct
    $ xxd gpe.sct
    00000000: 00a4 b909 90b4 1858 1487 bb13 a2cc 6770  .......X......gp
    00000010: 0a3c 3598 04f9 1bdf b8e3 77cd 0ec8 0ddc  .<5.......w.....
    00000020: 1000 0001 4bc7 e617 c800 0004 0300 4830  ....K.........H0
    00000030: 4602 2100 b9fe e206 f0f5 f600 93d5 e04c  F.!............L
    00000040: d2fd 75c9 e1fc a5c8 4812 a8b7 bc2c eb0c  ..u.....H....,..
    00000050: ee16 1fe9 0221 008a 5974 e1b6 a0e0 281a  .....!..Yt....(.
    00000060: 61e8 3447 895f 7ad4 2f70 f528 6133 a445  a.4G._z./p.(a3.E
    00000070: 4fd4 ab60 ba36 db                        O..`.6.
    $ 

License
-------

`ct-submit` is available under the terms of the ISC license, which is similar to
the 2-clause BSD license. See the `LICENSE` file for the copyright information
and licensing terms.

[ct]: http://www.certificate-transparency.org/
[apache]: https://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html
[nginx]: https://github.com/grahamedgecombe/nginx-ct
[go]: https://golang.org/
