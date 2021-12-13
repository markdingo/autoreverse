package delegation

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestRandomAlphas(t *testing.T) {
	for _, l := range []int{0, 1, 5, 10, 63} {
		s := randomAlphas(l)
		if len(s) != l {
			t.Error("randomAlphas returned wrong length. Want", l, "got", len(s), s)
			continue
		}
		for ix := 0; ix < l; ix++ {
			if s[ix] < 'A' || s[ix] > 'Z' {
				t.Error("randomAlphas return byte outside A-Z of", s[ix], s)
			}
		}
	}
}

func TestRandomHex(t *testing.T) {
	for _, l := range []int{0, 1, 5, 10, 63} {
		s := randomHex(l)
		if len(s) != l {
			t.Error("randomHex returned wrong length. Want", l, "got", len(s), s)
			continue
		}
		for ix := 0; ix < l; ix++ {
			if s[ix] >= 'a' && s[ix] <= 'f' {
				continue
			}
			if s[ix] >= '0' && s[ix] <= '9' {
				continue
			}
			t.Error("randomHex return byte outside 0-9, a-f of", s[ix], s)
		}
	}
}

func TestGenerateForward(t *testing.T) {
	pr := NewForwardProbe("example.org")
	q := pr.Question()

	// Strictly, we don't know what type the probe has generated, so don't test for
	// it.

	if !strings.HasSuffix(q.Name, "example.org.") {
		t.Error("q.Name should have trailing domain", q.Name)
	}
	if strings.HasPrefix(q.Name, "example.org") {
		t.Error("q.Name was not given a random prefix", q.Name)
	}
	if pr.answer.Header().Name != q.Name {
		t.Error("Answer does not match question", pr.answer)
	}

	if q.Qtype != pr.answer.Header().Rrtype {
		t.Error("Q and A rrtypes don't match", q.Qtype, pr.answer.Header().Rrtype)
	}
}

func TestGenerateReverseV4(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.0.2.44/24")
	if err != nil {
		t.Fatal("Setup error", err)
	}
	pr := NewReverseProbe("example.org", ipNet)
	q := pr.Question()

	if !strings.HasSuffix(q.Name, "in-addr.arpa.") {
		t.Error("Wrong reverse domain", q.Name)
	}
	if !strings.Contains(q.Name, "2.0.192.in") {
		t.Error("Wronge reverse name", q.Name)
	}
	if q.Qtype != dns.TypePTR || pr.answer.Header().Rrtype != dns.TypePTR {
		t.Error("All not TypePTR", q.Qtype, pr.answer.Header().Rrtype)
	}
	ptr := pr.answer.(*dns.PTR)
	if ptr == nil {
		t.Fatal("Wrong type set in answer", pr.answer)
	}
	if !strings.HasSuffix(ptr.Ptr, ".example.org.") {
		t.Error("PTR value not in domain", ptr.Ptr)
	}
	if strings.HasPrefix(ptr.Ptr, "example") {
		t.Error("PTR not prefixed with random", ptr.Ptr)
	}
	ar := strings.SplitN(q.Name, ".", 2)
	rv := ar[0] // Get random value
	matches := 0
	_, ipNet, err = net.ParseCIDR("192.0.2.44/24")
	if err != nil {
		t.Fatal("Setup error", err)
	}
	for ix := 0; ix < 5; ix++ {
		pr := NewReverseProbe("example.org", ipNet)
		q := pr.Question()
		if strings.HasPrefix(q.Name, rv) {
			matches++
		}
	}
	if matches > 2 {
		t.Error("Probe does not seem random enough")
	}
}

func TestGenerateReverseV6(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("2001:db8::1/64")
	if err != nil {
		t.Fatal("Setup error", err)
	}
	pr := NewReverseProbe("example.org", ipNet)
	q := pr.Question()

	if !strings.HasSuffix(q.Name, "ip6.arpa.") {
		t.Error("Wrong reverse domain", q.Name)
	}
	if !strings.Contains(q.Name, "8.b.d.0.1.0.0.2.ip6") {
		t.Error("Wronge reverse name", q.Name)
	}
	if q.Qtype != dns.TypePTR || pr.answer.Header().Rrtype != dns.TypePTR {
		t.Error("All not TypePTR", q.Qtype, pr.answer.Header().Rrtype)
	}
	ptr := pr.answer.(*dns.PTR)
	if ptr == nil {
		t.Fatal("Wrong type set in answer", pr.answer)
	}
	if !strings.HasSuffix(ptr.Ptr, ".example.org.") {
		t.Error("PTR value not in domain", ptr.Ptr)
	}
	if strings.HasPrefix(ptr.Ptr, "example") {
		t.Error("PTR not prefixed with random", ptr.Ptr)
	}
	ar := strings.SplitN(q.Name, ".", 4)
	rv := strings.Join(ar[0:3], ".") // Get random value
	matches := 0
	_, ipNet, err = net.ParseCIDR("2001:db8::1/64")
	if err != nil {
		t.Fatal("Setup error", err)
	}
	for ix := 0; ix < 5; ix++ {
		pr := NewReverseProbe("example.org", ipNet)
		q := pr.Question()
		if strings.HasPrefix(q.Name, rv) {
			matches++
		}
	}
	if matches > 2 {
		t.Error("Probe does not seem random enough")
	}
}

func TestQuestionMatches(t *testing.T) {
	pr, q := newReverse("192.0.2.21/24")
	if !pr.QuestionMatches(q) {
		t.Error("Question doesn't match self", q)
	}
	pr, q = newReverse("192.0.2.23/24")
	if !pr.QuestionMatches(q) {
		t.Error("Question doesn't match self", q)
	}

	pr, q = newReverse("2001:db8::1/64")
	if !pr.QuestionMatches(q) {
		t.Error("Question doesn't match self", q)
	}

	q1 := q
	q1.Qclass = dns.ClassCHAOS
	if pr.QuestionMatches(q1) {
		t.Error("Question matches modified Class self", q1)
	}
	q1 = q
	q1.Qtype = dns.TypeANY
	if pr.QuestionMatches(q1) {
		t.Error("Question matches modified Type self", q1)
	}
	q1 = q
	q1.Name = "Jubs"
	if pr.QuestionMatches(q1) {
		t.Error("Question matches modified Name self", q1)
	}
}

func TestAnswerMatches(t *testing.T) {
	prf := NewForwardProbe("example.org")
	if !prf.AnswerMatches(prf.Answer()) {
		t.Error("Forward Answer doesn't match self", prf.Answer())
	}
	prr, _ := newReverse("192.0.2.44/24")
	if !prr.AnswerMatches(prr.Answer()) {
		t.Error("Reverse Answer doesn't match self", prr.Answer())
	}
	prr, _ = newReverse("2001:db8::1/64")
	if !prr.AnswerMatches(prr.Answer()) {
		t.Error("Reverse Answer doesn't match self", prr.Answer())
	}

	ptr := prr.Answer().(*dns.PTR)
	if ptr == nil {
		t.Fatal("Setup error")
	}
	a := &dns.PTR{Ptr: ptr.Ptr}
	a.Hdr.Ttl = niceShortTTL * 100
	if prr.AnswerMatches(a) {
		t.Error("Reverse Answer unexpectedly matches", a, prr.Answer())
	}
	a.Hdr.Name = ptr.Hdr.Name
	if prr.AnswerMatches(a) {
		t.Error("Reverse Answer unexpectedly matches", a, prr.Answer())
	}
	a.Hdr.Rrtype = ptr.Hdr.Rrtype
	if prr.AnswerMatches(a) {
		t.Error("Reverse Answer unexpectedly matches", a, prr.Answer())
	}
	a.Hdr.Class = ptr.Hdr.Class
	if !prr.AnswerMatches(a) {
		t.Error("Reverse Answer should match now", a, prr.Answer())
	}
}

func newReverse(cidr string) (Probe, dns.Question) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("Setup error " + err.Error())
	}
	pr := NewReverseProbe("example.org", ipNet)
	q := pr.Question()

	return pr, q
}

func TestForwardProbeLabels(t *testing.T) {
	pr := NewForwardProbe("a.b.c.exaMple.cOm")
	iter := pr.Begin()
	z := pr.Zone(iter)
	if z != "b.c.example.com." {
		t.Error("Initial zone wrong", z)
	}

	z = pr.Zone(iter) // Shouldn't change unless iter is incremented
	if z != "b.c.example.com." {
		t.Error("Initial zone wrong", z)
	}

	lastZone := ""
	for iter = pr.Begin(); iter != pr.End(); iter = pr.Next(iter) {
		lastZone = pr.Zone(iter)
	}
	if lastZone != "com." {
		t.Error("Typical 'for loop' usaged failed", lastZone)
	}

	z = pr.Zone(pr.End())
	if z != "" {
		t.Error("Post 'for loop' returned non-empty string", z)
	}

	iter = pr.Begin()
	z = pr.Zone(iter)
	if z != "b.c.example.com." {
		t.Error("Reset didn't", z)
	}
}

func TestReverseProbeLabels(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		panic("Setup error " + err.Error())
	}
	pr := NewReverseProbe("example.org", ipNet)
	iter := pr.Begin()
	z := pr.Zone(iter)
	if z != "0.192.in-addr.arpa." { // One above the /24
		t.Error("Initial v4 zone wrong", z)
	}
	lastZone := ""
	for iter = pr.Begin(); iter != pr.End(); iter = pr.Next(iter) {
		lastZone = pr.Zone(iter)
	}
	if lastZone != "192.in-addr.arpa." {
		t.Error("Typical 'for loop' usaged failed", lastZone)
	}

	_, ipNet, err = net.ParseCIDR("2001:db8::/64")
	if err != nil {
		panic("Setup error " + err.Error())
	}
	begin := "0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa." // /64 up one label
	end := "0.1.0.0.2.ip6.arpa."                       // A /20
	pr = NewReverseProbe("example.org", ipNet)
	iter = pr.Begin()
	z = pr.Zone(iter)
	if z != begin {
		t.Error("Initial v6 zone wrong", z)
	}

	lastZone = ""
	for ; iter != pr.End(); iter = pr.Next(iter) {
		lastZone = pr.Zone(iter)
	}
	if lastZone != end {
		t.Error("Typical 'for loop' usaged failed", lastZone)
	}

	lastZone = ""
	for iter = pr.Begin(); iter != pr.End(); iter = pr.Next(iter) {
		lastZone = pr.Zone(iter)
	}
	if lastZone != end {
		t.Error("Typical 'for loop' usaged failed", lastZone)
	}

	z = pr.Zone(pr.End())
	if z != "" {
		t.Error("Post 'for loop' returned non-empty string", z)
	}

	iter = pr.Begin()
	z = pr.Zone(iter)
	if z != begin {
		t.Error("Reset didn't", z)
	}
}

func TestIndependentIters(t *testing.T) {
	pr := NewForwardProbe("A.big.Long.set.Of.Labels.example.com")
	it1 := pr.Begin()
	it2 := pr.Begin()
	z1 := pr.Zone(it1)
	z2 := pr.Zone(it2)
	it1 = pr.Next(it1)
	it1 = pr.Next(it1)
	it1 = pr.Next(it1)

	z1a := pr.Zone(it1)
	z2a := pr.Zone(it2)
	if z1a == z1 {
		t.Error("Independent iters interfere with first", z1a)
	}
	if z2a != z2 {
		t.Error("Independent iters interfere with second", z2a)
	}
}
