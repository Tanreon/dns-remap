package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	dnsapi "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	iptables IIptables
	address  string
}

func NewServer(address string, resolvingSubnet string) (server *Server, err error) {
	server = &Server{
		address: address,
	}

	//

	_, ipNet, err := net.ParseCIDR(resolvingSubnet)
	if err != nil {
		return server, fmt.Errorf("parsing CIDR error: %w", err)
	}

	server.iptables = NewIptables(ipNet)

	//

	dnsapi.HandleFunc(".", server.handleServe)

	var wg sync.WaitGroup
	wg.Add(2)
	go server.ListenAndServeTCP(&wg)
	go server.ListenAndServeUDP(&wg)
	wg.Wait()

	return server, err
}

func (s *Server) handleServe(w dnsapi.ResponseWriter, r *dnsapi.Msg) {
	defer w.Close()

	//

	dnsMessage := &dnsapi.Msg{}
	dnsMessage.AuthenticatedData = true
	dnsMessage.Authoritative = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.SetReply(r)
	dnsMessage.Compress = false

	//

	dnsUpstream := &dnsapi.Client{}
	dnsUpstream.Timeout = time.Second * 5

	//

	dnsUpstreamResponse, _, err := dnsUpstream.Exchange(r, net.JoinHostPort(config.UpstreamDns.Server, config.UpstreamDns.Port))
	if err != nil {
		dnsMessage.SetRcode(r, dnsapi.RcodeServerFailure)
		w.WriteMsg(dnsMessage)

		log.Errorf("%s <-> %d/%s error: %v", w.RemoteAddr(), r.Question[0].Qtype, r.Question[0].Name, err)
		return
	}

	if dnsUpstreamResponse.Rcode != dnsapi.RcodeSuccess {
		dnsMessage.SetRcode(r, dnsUpstreamResponse.Rcode)
		w.WriteMsg(dnsMessage)

		//log.Errorf("%s <-> %d/%s rcode not success: %v", w.RemoteAddr(), r.Question[0].Qtype, r.Question[0].Name, dnsUpstreamResponse.Rcode)
		return
	}

	for _, ns := range dnsUpstreamResponse.Ns {
		dnsMessage.Ns = append(dnsMessage.Ns, ns)

		log.Debugf("request ns from %s, type: %d, %s", w.RemoteAddr(), ns.Header().Rrtype, ns.Header().Name)
	}

	for _, extra := range dnsUpstreamResponse.Extra {
		dnsMessage.Extra = append(dnsMessage.Extra, extra)

		//log.Debugf("request extra from %s, type: %d", w.RemoteAddr(), extra.Header().Rrtype)
	}

	for _, answer := range dnsUpstreamResponse.Answer {
		switch answer.Header().Rrtype {
		case dnsapi.TypeA:
			var fakeIp *net.IP
			cacheKey := "A/" + answer.(*dnsapi.A).A.String() // + "/" + strconv.Itoa(int(answer.Header().Ttl))

			if s.iptables.Contains(cacheKey) {
				fakeIp = s.iptables.UpdateGet(cacheKey, int(answer.Header().Ttl)+30)
			} else {
				fakeIp = s.iptables.Put(cacheKey, &answer.(*dnsapi.A).A, int(answer.Header().Ttl)+30, answer.Header().Name, "A")
			}

			dnsMessage.Answer = append(dnsMessage.Answer, &dnsapi.A{
				Hdr: dnsapi.RR_Header{Name: answer.Header().Name, Rrtype: answer.Header().Rrtype, Class: answer.Header().Class, Ttl: answer.Header().Ttl},
				A:   *fakeIp,
			})

			log.Infof("request faked %s <-> %s, type: A, %s", w.RemoteAddr(), answer.(*dnsapi.A).A.String(), answer.Header().Name)
		default:
			dnsMessage.Answer = append(dnsMessage.Answer, answer)

			log.Infof("request from %s, type: %d, %s", w.RemoteAddr(), answer.Header().Rrtype, answer.Header().Name)
		}
	}

	w.WriteMsg(dnsMessage)
}

// ListenAndServeUDP listen and serves on udp port.
func (s *Server) ListenAndServeUDP(wg *sync.WaitGroup) {
	wg.Done()

	log.Infof("listening UDP on %s", s.address)

	server := &dnsapi.Server{Addr: s.address, Net: "udp", ReusePort: true}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("failed to listen on %s, error: %v", s.address, err)
	}
}

// ListenAndServeTCP listen and serves on tcp port.
func (s *Server) ListenAndServeTCP(wg *sync.WaitGroup) {
	wg.Done()

	log.Infof("listening TCP on %s", s.address)

	server := &dnsapi.Server{Addr: s.address, Net: "tcp", ReusePort: true}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("failed to listen on %s, error: %v", s.address, err)
	}
}
