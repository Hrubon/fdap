# FDAP

This is a canonical implementation of a high-performance in-memory directory
based on the Concise Binary Object Representation (CBOR).

## `fdapdiag`

  fdapdiag -t tcp -h 127.0.0.1 -p 20893
  	$> insert "{username: 'foo', password: 'bar',}";
  	$> search "username == 'foo' & password = 'bar'";
  	$> delete "id >= 10";

There is a default user account created after the daemon startup. It is
hardcoded into the source code. The username is 'admin', and the password is
'admin'. Please use this account for managing the example directory.

