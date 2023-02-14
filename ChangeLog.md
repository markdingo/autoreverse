### v1.4.0 - 2023-02-14
  * Added RRL support with https://github.com/markdingo/rrl
# autoreverse Change Log
  * Replace dns.MsgAcceptFunc to ensure rfc7873#5.4 queries are accepted
### v1.3.0 - 2022-02-10
  * Move cmd code to top level so "go install" just works
  * Remove compact logging - it's confusing and doesn't save much
  * Add missing qType=PTR test to synth checks
  * Don't bother calling synth functions for qName == authority
  * Adapt stats reporting to new query logic
### v1.2.0 -- 2022-01-27
  * Refactor query dispatch logic to take advantage of the tree database
  * Reimplement database as a tree to better distinguish NXDomain vs NOError
  * Have ConstraintReport() report the chroot path
  * Wrap all returned errors via fmt.Errorf() with original error
  * More sophisticated treatment of cookie timestamps
### v1.1.0 -- 2021-12-23
  * Add rfc7873, rfc9018 DNS Cookie support
  * Add a trigger reason to the zone reload log message
  * Use dnsutil.*ToString instead of dns.*ToString to render unmapped values
  * Fix most concerns expressed by https://goreportcard.com/
### v1.0.1 -- 2021-12-14
  * Rename ":" test files to "_" to help github and zip
### v1.0.0 -- 2021-12-13
  * Initial public release.
