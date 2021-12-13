package main

import (
	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/pregen"
)

// Called if Qclass = CHAOS. Nothing else has been checked yet
func (t *server) serveCHAOS(wtr dns.ResponseWriter, req *request) {
	var response string
	switch req.qName {
	case "version.bind.":
		response = programName
	case "version.server.":
		response = pregen.Version + " " + pregen.ReleaseDate
	case "authors.bind.":
		response = t.cfg.projectURL
	case "hostname.bind.":
		response = t.cfg.nsid
	case "id.server.":
		response = t.cfg.nsid
	default:
		t.serveRefused(wtr, req)
		return
	}
	req.response.SetReply(req.query)
	txt := new(dns.TXT)
	txt.Hdr.Name = req.question.Name
	txt.Hdr.Class = req.question.Qclass
	txt.Hdr.Rrtype = req.question.Qtype
	txt.Hdr.Ttl = t.cfg.TTLAsSecs
	txt.Txt = append(txt.Txt, response)

	req.response.Answer = append(req.response.Answer, txt)
	t.writeMsg(wtr, req)
}
