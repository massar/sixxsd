# Contributing

sixxsd is mostly provided as a historic insight into the opertion of forwarding of tunneled packets as done on SixXS PoPs.

The code has been released so that people can learn from it.

Please note that sixxsd was designed and written with specific constraints in mind (e.g. a /40 per PoP, thousands of tunnels and secure underlying networks for control etc.)

## Questions about the code

For questions about the system and constructs used in the code, do not hesitate to file an issue so that questions can be answered.

## Feature Requests

Feature requests won't be accepted, as, the code is historic and should not be used anymore...

## Get Native IPv6!

As IPv6 has been deployed for well over 20 years, please try to get native IPv6.

## IPv6 between disconnected sites

In cases where one wants to build tunnels between sites where IPv6 is not available, or just to cross boundaries, we heavily suggest using Wireguard.
Please see the README.md for some more details.

## Background on programming language / Writing a new tunneling system

For the timeframe where this code was used, C was great, especially for the speed and to access the lower level parts of the system.
I did take great care in input sanitation and shielding from buffer overflows, parsing errors etc, though likely some still might be there.
If there are any weird bugs and one notices them, do file an issue so that they can be corrected.

As it is 2018, writing a new tunneling system would better be done in a trusted language instead of C.
We heavily recommend Go as a very stable language which has great access to fast cryptographic functions.

All of the tunnels in sixxsd are in clear text, hence, visible to the many eyes on the Internet.

I have giving several talks about the subject as can be found in the (presentations)[https://jeroen.massar.ch/presentations/] section of my homepage.
