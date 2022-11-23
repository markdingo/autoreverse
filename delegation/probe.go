package delegation

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
)

const (
	niceShortTTL = 3 // Just in case a cache tries to intervene
)

// zoneCutIterator is a faux iterator for zone cut searching: See Probe.Begin(),
// Probe.End() and Probe.Next() for how we implement a C++ iterator in go.
type zoneCutIterator struct {
	ix int
}

// Probe contains the details for "probing" a name to find the zone cut and self-identify
// as a particular name server by exchanging a unique-ish question/response. The
// uniqueness is there to mitigate the risk of possible over-helpful muddle-ware
// intercepting DNS traffic and perhaps caching or mangling it. Hopefully unlikely in our
// circumstances but it doesn't hurt to be too careful.
//
// For the self-identifying probe to succeed, ultimately the target domain of the probe
// must be a real domain on the global DNS which is delegated back to this program
// instance.
//
// For zone cut discovery the zoneLabels slice contains the first candidate parents of the
// target which are one label up. To walk up the DNS tree in search of the zone cut use
// the following "for loop".
//
//	for iter := probe.Begin(); iter != probe.End(); iter = probe.Next(iter) {
//	    zoneName := probe.Zone(iter)
//	    ...
//	}
//
// Once created, a Probe is never modified so it can be freely shared between
// go-routines. Iterators, however, cannot be shared and can only be used on the Probe
// which creates them.
type Probe interface {
	Target() string // Original target at Probe creation time
	Question() dns.Question
	Answer() dns.RR
	QuestionMatches(dns.Question) bool
	AnswerMatches(dns.RR) bool

	Begin() zoneCutIterator
	End() zoneCutIterator
	Next(zoneCutIterator) zoneCutIterator
	Zone(zoneCutIterator) string
}

type commonProbe struct {
	target        string
	zoneLabels    []string        // For walking up the DNS tree
	minimumLabels int             // Never allow fewer labels than this limit
	end           zoneCutIterator // Last+1 in iterator parlance

	question dns.Question // What is sent
	answer   dns.RR       // What we return
}

type forwardProbe struct {
	commonProbe
}

type reverseProbe struct {
	ptr   string
	ipNet net.IPNet // Supplied to New
	commonProbe
}

// Randomize the PRNG. Tests can call Seed() to set predictable sequences.
func init() {
	rand.Seed(time.Now().UnixNano())
}

// randomAlphas creates a string of 'n' random alpha characters. It uses an array of
// "universal" characters so that this code works for ASCII, FIELDATA and
// EBCDIC. Future-proofing and all that... If this string is used to create a qName, make
// sure to clean up the case with a call to dns.CanonicalName().
func randomAlphas(n int) string {
	const randAlphaSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphas := make([]byte, 0, n)
	for ; n > 0; n-- {
		alphas = append(alphas, randAlphaSet[rand.Int31n(int32(len(randAlphaSet)))])
	}

	return string(alphas)
}

// randomHex creates a string of 'n' random hexadecimal characters.
func randomHex(n int) string {
	const randHexSet = "01234567890abcdef"
	hex := make([]byte, 0, n)
	for ; n > 0; n-- {
		hex = append(hex, randHexSet[rand.Int31n(int32(len(randHexSet)))])
	}

	return string(hex)
}

func (t *commonProbe) Target() string {
	return t.target
}

func (t *commonProbe) Question() dns.Question {
	return t.question
}

func (t *commonProbe) Answer() dns.RR {
	return t.answer
}

// NewForwardProbe creates a conservative, semi-random AAAA RR and corresponding question.
func NewForwardProbe(target string) *forwardProbe {
	t := &forwardProbe{}
	t.target = dns.CanonicalName(target)
	t.zoneLabels = strings.Split(t.target, ".")

	// Generate the probe
	qName := dns.CanonicalName(fmt.Sprintf("%s.%s", randomAlphas(5), t.target))
	t.question.Name = qName
	t.question.Qclass = dns.ClassINET
	t.question.Qtype = dns.TypeAAAA

	ip := net.ParseIP("2001:db8::" + randomHex(4) + ":" + randomHex(4) + ":" + randomHex(4))
	aaaa := &dns.AAAA{AAAA: ip}
	aaaa.Hdr.Name = qName
	aaaa.Hdr.Rrtype = t.question.Qtype
	aaaa.Hdr.Class = t.question.Qclass
	aaaa.Hdr.Ttl = niceShortTTL

	t.answer = aaaa

	// Move one label up to set the starting point for the zone cut search. Beware:
	// the caller may inadvertently supply a domain with too few labels to pop.

	if len(t.zoneLabels) > 1 {
		t.zoneLabels = t.zoneLabels[1:] // Trim from target to get parent
	}

	t.minimumLabels = 2 // Stop at TLD in forward direction (last label is root)

	if len(t.zoneLabels) >= t.minimumLabels { // End is last + 1
		t.end.ix = len(t.zoneLabels) - t.minimumLabels + 1
	}

	return t
}

// NewReverseProbe creates a conservative, semi-random PTR and corresponding question
// which hopefully has the same likelihood of success as that of a forward prone.
//
// The target zone is based on the prefix length of the supplied CIDR. Ultimately the
// target zone must be a real domain which is delegated back to this program instance for
// self-identify to work.
//
// For zone cut discovery we start with the first candidate parents of the target which
// are one label up. For ipv6 it's likely the parent will be multiple labels up, but
// probes are also used with legacy ipv4 addresses which will typically have parents just
// one label up.
//
// The supplied ptrText is used to formulate the response PTR text and normally it will be
// the forward domain name.
func NewReverseProbe(ptrText string, ipNet *net.IPNet) *reverseProbe {
	ip := ipNet.IP
	t := &reverseProbe{ptr: ptrText, ipNet: *ipNet}
	t.target = dnsutil.IPToReverseQName(ip)
	t.zoneLabels = strings.Split(t.target, ".")

	// Generate the probe
	labels := make([]string, len(t.zoneLabels)) // Take a copy as we don't want to
	copy(labels, t.zoneLabels)                  // modify the underlying array
	if ip4 := ip.To4(); ip4 != nil {
		t.minimumLabels = 1 + 3                           // Never less than a /8
		labels[0] = fmt.Sprintf("%d", 1+rand.Int31n(253)) // Avoid .0 and .255 ... for reasons.
	} else if ip6 := ip.To16(); ip6 != nil {
		t.minimumLabels = 5 + 3                          // Never less than a /20
		labels[0] = fmt.Sprintf("%x", 1+rand.Int31n(14)) // Avoid 0x0 and 0xf ...
		labels[1] = fmt.Sprintf("%x", 1+rand.Int31n(14)) // for no reason
		labels[2] = fmt.Sprintf("%x", 1+rand.Int31n(14))
	}
	qName := strings.Join(labels, ".")

	t.question.Name = qName
	t.question.Qclass = dns.ClassINET
	t.question.Qtype = dns.TypePTR

	ptr := &dns.PTR{Ptr: dns.CanonicalName(randomAlphas(5) + "." + ptrText)}
	ptr.Hdr.Name = qName
	ptr.Hdr.Rrtype = t.question.Qtype
	ptr.Hdr.Class = t.question.Qclass
	ptr.Hdr.Ttl = niceShortTTL

	t.answer = ptr

	// Use the CIDR prefix length to trim the zoneLabels.

	ones, bits := ipNet.Mask.Size()
	var remove int
	if bits == 32 { // ipv4
		remove = 4 - ones/8 // Labels to remove
	} else {
		remove = 32 - ones/4 // Labels to remove
	}

	// Make sure the number of labels to remove isn't crazy
	if (len(t.zoneLabels) - remove) <= t.minimumLabels {
		remove = len(t.zoneLabels) - t.minimumLabels
	}
	t.zoneLabels = t.zoneLabels[remove:]
	t.target = strings.Join(t.zoneLabels, ".") // Update target with CIDR qName

	// Move one label up to define the starting point for the zone cut search. Protect
	// against crazy short number of labels, tho this shouldn't be possible, we can't
	// be sure of what the caller has passed in.

	if len(t.zoneLabels) > 1 {
		t.zoneLabels = t.zoneLabels[1:] // Trim from target to get parent
	}

	if len(t.zoneLabels) >= t.minimumLabels { // End is last + 1
		t.end.ix = len(t.zoneLabels) - t.minimumLabels + 1
	}

	return t
}

// QuestionMatches returns true if the question matches the probe. This is normally asked
// by the server-side to determine whether to send the answer as a response.
func (t *commonProbe) QuestionMatches(match dns.Question) bool {
	return match.Qclass == t.answer.Header().Class &&
		match.Qtype == t.answer.Header().Rrtype &&
		dns.CanonicalName(match.Name) == t.answer.Header().Name
}

// AnswerMatches returns true if the answer provided near enough matches our answer. Note
// that answers may not be identical as they could have passed thru a cache or other
// meddleware.
func (t *commonProbe) AnswerMatches(match dns.RR) bool {
	return dnsutil.RRIsEqual(match, t.answer)
}

// Begin returns a zoneCutIterator for walking up the DNS tree.
func (t *commonProbe) Begin() (iter zoneCutIterator) {
	return
}

// Next moves the zoneCutIterator to the next item.
func (t *commonProbe) Next(iter zoneCutIterator) zoneCutIterator {
	if iter.ix < t.end.ix {
		iter.ix++
	}

	return iter
}

// End defines the termination point for a zoneCutIterator.
func (t *commonProbe) End() zoneCutIterator {
	return t.end
}

// Zone returns the current zone relative to the supplied iterator. An empty string is
// returned if the Probe has iterated past the End() of the Probe.
func (t *commonProbe) Zone(iter zoneCutIterator) string {
	if iter.ix >= t.end.ix {
		return ""
	}

	return strings.Join(t.zoneLabels[iter.ix:], ".")
}
