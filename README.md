# Encrypted Sessions Test Suite #

This is a test suite for client implementations of [XEP-0116 (Encrypted Session Negotiation)][XEP-0116] and the XEPs it is based on.

It was originally written as part of Google Summer of Code 2007 for the XMPP Software Foundation by [Brendan Taylor][bct], and is released under the MIT/X11 license (see the LICENSE file).

## Requirements ##

- [PyCrypto][]
- uuid.py (in Python 2.5's stdlib)

## Details ##

The suite is implemented as a server component that responds to a number of different JIDs, each responsible for a different set of tests:

- xep201@<component>
  - tests
- xep155@<component>:
  - simple generic session negotiation
- xep200@<component>
  - message encryption and decryption with hardcoded keys
- xep217@<component>
  - a simplified profile of XEP-0116
- sigmai@<component>
  - XEP-0116 3-message negotiation
- tampered@<component>
  - runs a XEP-0116 negotiation with data that your client should reject

To run the suite, you'll need to set up your server to accept a component connection. Then:

    ./main.py <component-name> <server-hostname> <port> <secret>

There should also be a copy of the suite running at testsuite.necronomicorp.com

[bct]: http://necronomicorp.com/bct
[XEP-0116]: http://www.xmpp.org/extensions/xep-0116.html
[PyCrypto]: http://www.amk.ca/python/code/crypto
