/*
Package resolver defines an interface and provides a concrete implementation of a
Frankestein DNS resolver service which is an amalgam of the standard go net package
resolver functions and the github.com/miekg/dns package.

The sole reason this package exists is to present resolving as an interface which can be
mocked for testing purposes. It only covers functions used by autoreverse which reach out
to the network. All other functions are accessed directly.
*/
package resolver
