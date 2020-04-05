#!/bin/bash
# PKIXTest uses real certificates for testing, which comes with expiration dates
# when you hit that expiration problem, get a new chain of certificates from this command.
#
# It prints several certificates. The first is that of the site, followed by CA cert that signs it.
# For this test we want one intermediary CA and another root CA, totaling 3 certs
openssl s_client -showcerts -connect www.google.com:443
