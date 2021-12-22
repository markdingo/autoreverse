package main

import (
	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/pregen"
)

var commonCHAOSPrefix = programName + " " + pregen.Version + " " + pregen.ReleaseDate

// Called if Qclass = CHAOS and Qtype = TXT. It seems silly to be parsimonious with each
// query name. Given there is no defined syntax and each auth server seems to do something
// different, why not just blat all the details out in all cases?
func (t *server) serveCHAOS(wtr dns.ResponseWriter, req *request) {
	var response string
	switch req.qName {
	case "version.bind.", "version.server.", "authors.bind.":
		response = commonCHAOSPrefix + " " + t.cfg.projectURL
	case "hostname.bind.", "id.server.":
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
