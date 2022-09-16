// sd-test-srv runs a simple service discovery system; it returns two hardcoded
// IP addresses for every A query.
package main

import (
	"flag"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Rcode = dns.RcodeSuccess

	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeServerFailure
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("ERROR: Failed to write message %q: %v", m, err)
		}
		return
	}

	qname := r.Question[0].Name

	if r.Question[0].Qtype == dns.TypeA {
		hdr := dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		}
		// These two hardcoded IPs correspond to the configured addresses for boulder
		// in docker-compose.yml. In our Docker setup, boulder is present on two
		// networks, rednet and bluenet, with a different IP address on each. This
		// allows us to test load balance across gRPC backends.
		if strings.HasSuffix(qname, "1.boulder.") {
			m.Answer = append(m.Answer, &dns.A{
				A:   net.ParseIP("10.77.77.77"),
				Hdr: hdr,
			})
		} else if strings.HasSuffix(qname, "2.boulder.") {
			m.Answer = append(m.Answer, &dns.A{
				A:   net.ParseIP("10.88.88.88"),
				Hdr: hdr,
			})
		} else if strings.HasSuffix(qname, ".boulder.") || qname == "boulder." {
			m.Answer = append(m.Answer, &dns.A{
				A:   net.ParseIP("10.77.77.77"),
				Hdr: hdr,
			}, &dns.A{
				A:   net.ParseIP("10.88.88.88"),
				Hdr: hdr,
			})
		} else {
			m.Rcode = dns.RcodeServerFailure
		}
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("ERROR: Failed to write message %q: %v", m, err)
		}
		return
	}

	if r.Question[0].Qtype == dns.TypeSRV {
		hdr := dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    0,
		}
		// A SRV record contains host:port combinations. The hosts in turn will be
		// looked up in a subsequent query. These will resolve to 10.77.77.77:8053
		// and 10.77.77.77:8054, respectively. The former will have challtestsrv
		// listening on it. The latter doesn't have anything listening on it, but
		// that's fine; the VA will just retry on a working port.
		m.Answer = append(m.Answer, &dns.SRV{
			Target: "dns1.boulder.",
			Port:   8053,
			Hdr:    hdr,
		}, &dns.SRV{
			Target: "dns2.boulder.",
			Port:   8054,
			Hdr:    hdr,
		})
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("ERROR: Failed to write message %q: %v", m, err)
		}
		return
	}

	// Just return a NOERROR message for non-A, non-SRV questions
	err := w.WriteMsg(m)
	if err != nil {
		log.Printf("ERROR: Failed to write message %q: %v", m, err)
	}
}

func main() {
	listen := flag.String("listen", ":53", "Address and port to listen on.")
	flag.Parse()
	if *listen == "" {
		flag.Usage()
		return
	}
	dns.HandleFunc(".", dnsHandler)
	go func() {
		srv := dns.Server{
			Addr:         *listen,
			Net:          "tcp",
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
		}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}()
	srv := dns.Server{
		Addr:         *listen,
		Net:          "udp",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}
	err := srv.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
