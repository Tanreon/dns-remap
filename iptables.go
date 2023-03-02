package main

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phf/go-queue/queue"

	log "github.com/sirupsen/logrus"
)

const IPTABLES_BIN = "/usr/sbin/iptables-nft"
const LONG_TTL = 60 * 60

type IptablesItem struct {
	fakeIp  *net.IP
	trueIp  *net.IP
	ttl     int
	expire  time.Time
	domain  string
	dnsType string
}

// Iptables Cache is the struct of iptables.
type Iptables struct {
	cache         map[string]*IptablesItem
	rwMutex       sync.RWMutex
	ipBindingPool *queue.Queue
}

type IIptables interface {
	Contains(key string) bool
	UpdateGet(key string, ttl int) (fakeIp *net.IP)
	Put(key string, trueIp *net.IP, ttl int, domain, dnsType string) (fakeIp *net.IP)
}

func NewIptables(ipNet *net.IPNet) (iptables *Iptables) {
	iptables = &Iptables{
		cache: make(map[string]*IptablesItem),
	}

	//

	ipBindingPool := queue.New()

	ipPool := make([]*net.IP, 0)
	for index := 0; true; index++ {
		v := uint(ipNet.IP[0])<<24 + uint(ipNet.IP[1])<<16 + uint(ipNet.IP[2])<<8 + uint(ipNet.IP[3])
		v += uint(index)

		ip := net.IPv4(byte((v>>24)&0xFF), byte((v>>16)&0xFF), byte((v>>8)&0xFF), byte(v&0xFF))

		if !ipNet.Contains(ip) {
			break
		}

		ipPool = append(ipPool, &ip)
	}

	//

	busyIPs := iptables.parseRules()

	for _, ip := range ipPool {
		isIpBusy := false

		for _, busyIp := range busyIPs {
			if busyIp.Equal(*ip) {
				isIpBusy = true

				break
			}
		}

		if !isIpBusy {
			ipBindingPool.PushFront(ip)
		}
	}

	iptables.ipBindingPool = ipBindingPool

	//

	go iptables.removeExpired()

	return
}

//// Len returns the length of iptables.
//func (c *Iptables) Len() int {
//	return len(c.cache)
//}

func (i *Iptables) removeExpired() {
	for range time.Tick(time.Second * 30) {
		log.Debugf("starting removing expired job")

		i.rwMutex.Lock()

		itemsToRemove := make([]*IptablesItem, 0) // попытка сократить время доступа \ добавления нового правила в iptables при одновременной записи \ удалении элементов

		for k, v := range i.cache {
			if time.Now().Before(v.expire.Add(time.Second * 30)) {
				//if time.Now().Before(v.expire) {
				continue
			}

			//i.removeRule(v.fakeIp, v.trueIp, v.ttl, v.domain, v.dnsType)
			//i.ipBindingPool.PushFront(v.fakeIp)
			itemsToRemove = append(itemsToRemove, v)

			i.ipBindingPool.PushFront(v.fakeIp)
			delete(i.cache, k)
			//delete(i.cache, k)

			//log.Debugf("put %s back to IP binding pool", v.fakeIp.String())
		}

		i.rwMutex.Unlock()

		for _, v := range itemsToRemove {
			i.removeRule(v.fakeIp, v.trueIp, v.ttl, v.domain, v.dnsType)

			log.Debugf("put %s back to IP binding pool", v.fakeIp.String())
		}

		log.Debugf("removing expired job end")
	}
}

func (i *Iptables) parseRules() (busyIPs []*net.IP) {
	doneChan := make(chan bool, 1)

	pattern := regexp.MustCompile(`DNAT\s+all\s+--\s+\d+\.\d+\.\d+\.\d+/\d+\s+(?P<FakeIP>\d+.\d+.\d+.\d+)\s+/\*\s*(?P<Options>.*)\s*\*/\s+to:(?P<TrueIP>\d+.\d+.\d+.\d+)`)

	cmd := exec.Command(IPTABLES_BIN,
		"-w", "10",
		"-t", "nat",
		"-nL", "dnsmap",
	)

	// create a pipe for the output of the script
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(cmdReader)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()

			if !pattern.MatchString(line) {
				continue
			}

			ruleMatches := pattern.FindAllStringSubmatch(line, 1)
			if len(ruleMatches) < 1 {
				panic("parsing iptables rule fail")
			}

			fakeIpIndex := pattern.SubexpIndex("FakeIP")
			trueIpIndex := pattern.SubexpIndex("TrueIP")
			optionsIndex := pattern.SubexpIndex("Options")

			fakeIp := net.ParseIP(ruleMatches[0][fakeIpIndex])
			trueIp := net.ParseIP(ruleMatches[0][trueIpIndex])

			var domain string
			var dnsType string
			var ttl int
			//var expire time.Time

			optionsLine := ruleMatches[0][optionsIndex]
			options := strings.Split(optionsLine, ";")
			for _, option := range options {
				optionPieces := strings.Split(option, "=")
				if len(optionPieces) < 2 {
					continue
				}

				optionTitle := optionPieces[0]
				optionValue := optionPieces[1]

				switch optionTitle {
				case "domain":
					domain = strings.ToLower(strings.TrimSpace(optionValue))
				case "type":
					dnsType = strings.TrimSpace(optionValue)
				case "ttl":
					ttl, err = strconv.Atoi(optionValue)
					if err != nil {
						panic(err)
					}
					//case "expire":
					//	timestamp, err := strconv.ParseInt(optionValue, 10, 64)
					//	if err != nil {
					//		panic(err)
					//	}
					//
					//	expire = time.Unix(timestamp, 0)
				}
			}

			//

			//if time.Now().After(expire) {
			//	i.removeRule(&fakeIp, &trueIp, expire, domain, dnsType)
			//	log.Debugf("remove expired %s <-> %s", fakeIp.String(), trueIp.String())
			//
			//	continue
			//}

			item := &IptablesItem{
				fakeIp:  &fakeIp,
				trueIp:  &trueIp,
				ttl:     ttl,
				expire:  time.Now().Add(time.Second * time.Duration(ttl)),
				domain:  domain,
				dnsType: dnsType,
			}

			i.cache[i.cacheKey(item)] = item
			busyIPs = append(busyIPs, &fakeIp)

			log.Debugf("put %s to cache %s <-> %s with TTL %d sec", i.cacheKey(item), fakeIp.String(), trueIp.String(), ttl)
		}

		doneChan <- true
	}()

	err = cmd.Start()
	if err != nil {
		panic(err)
	}

	err = cmd.Wait()
	if err != nil {
		panic(err)
	}

	<-doneChan

	return
}

func (i *Iptables) appendRule(fakeIp, trueIp *net.IP, ttl int, domain, dnsType string) {
	cmd := exec.Command(IPTABLES_BIN,
		"-w", "10",
		"-t", "nat",
		"-A", "dnsmap",
		"-d", fmt.Sprintf("%s", fakeIp.String()),
		"-j", "DNAT",
		"--to", fmt.Sprintf("%s", trueIp.String()),
		"-m", "comment", "--comment", fmt.Sprintf("ttl=%d;domain=%s;type=%s;", ttl, strings.ToLower(domain), dnsType),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputLines := strings.Split(string(output), "\n")
		for _, line := range outputLines {
			log.Error(line)
		}

		log.Errorf("iptables cmd line: %v", cmd.Args)
		log.Fatalf("iptables error: %v", err)
	}
}

func (i *Iptables) insertRule(fakeIp, trueIp *net.IP, ttl int, domain, dnsType string) {
	cmd := exec.Command(IPTABLES_BIN,
		"-w", "10",
		"-t", "nat",
		"-I", "dnsmap",
		"-d", fmt.Sprintf("%s", fakeIp.String()),
		"-j", "DNAT",
		"--to", fmt.Sprintf("%s", trueIp.String()),
		"-m", "comment", "--comment", fmt.Sprintf("ttl=%d;domain=%s;type=%s;", ttl, strings.ToLower(domain), dnsType),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputLines := strings.Split(string(output), "\n")
		for _, line := range outputLines {
			log.Error(line)
		}

		log.Errorf("iptables cmd line: %v", cmd.Args)
		log.Fatalf("iptables error: %v", err)
	}
}

func (i *Iptables) removeRule(fakeIp, trueIp *net.IP, ttl int, domain, dnsType string) {
	cmd := exec.Command(IPTABLES_BIN,
		"-w", "10",
		"-t", "nat",
		"-D", "dnsmap",
		"-d", fmt.Sprintf("%s", fakeIp.String()),
		"-j", "DNAT",
		"--to", fmt.Sprintf("%s", trueIp.String()),
		"-m", "comment", "--comment", fmt.Sprintf("ttl=%d;domain=%s;type=%s;", ttl, strings.ToLower(domain), dnsType),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputLines := strings.Split(string(output), "\n")
		for _, line := range outputLines {
			log.Error(line)
		}

		log.Errorf("iptables cmd line: %v", cmd.Args)
		log.Fatalf("iptables error: %v", err)
	}
}

func (i *Iptables) putCache(key string, trueIp *net.IP, ttl int, domain, dnsType string) (fakeIp *net.IP) {
	//if item, present := i.cache[key]; present {
	//	fakeIp = item.fakeIp
	//	return
	//}

	if i.ipBindingPool.Len() <= 0 {
		panic("fake IP is nil, try to scale up fake IP pool")
	}
	fakeIp = i.ipBindingPool.PopBack().(*net.IP)

	i.cache[key] = &IptablesItem{
		fakeIp:  fakeIp,
		trueIp:  trueIp,
		ttl:     ttl,
		expire:  time.Now().Add(time.Duration(ttl) * time.Second),
		domain:  domain,
		dnsType: dnsType,
	}

	return
}

// Put an item into iptables, invalid after ttl seconds.
func (i *Iptables) Put(key string, trueIp *net.IP, ttl int, domain, dnsType string) (fakeIp *net.IP) {
	i.rwMutex.Lock()
	fakeIp = i.putCache(key, trueIp, ttl, domain, dnsType)
	i.rwMutex.Unlock()

	i.insertRule(fakeIp, trueIp, ttl, domain, dnsType)

	log.Debugf("insert %s <-> %s with key %s and TTL %d sec", fakeIp.String(), trueIp.String(), key, ttl)

	return
}

func (i *Iptables) UpdateGet(key string, ttl int) (fakeIp *net.IP) {
	i.rwMutex.Lock()
	defer i.rwMutex.Unlock()

	if value, present := i.cache[key]; present {
		//if value.ttl != ttl {
		//	log.Debugf("for domain %s detected changed TTL updating %d <-> %d", value.domain, value.ttl, ttl)
		//	//i.removeRule(value.fakeIp, value.trueIp, value.ttl, value.domain, value.dnsType)
		//	i.insertRule(value.fakeIp, value.trueIp, ttl, value.domain, value.dnsType)
		//	i.cache[key].ttl = ttl
		//} else {
		//	log.Debugf("for domain %s UNdetected changed TTL updating %d <-> %d", value.domain, value.ttl, ttl)
		//}

		i.cache[key].expire = time.Now().Add(time.Second * time.Duration(ttl))
		return value.fakeIp
	}

	return
}

func (i *Iptables) Contains(key string) bool {
	i.rwMutex.RLock()
	defer i.rwMutex.RUnlock()

	if _, present := i.cache[key]; present {
		return true
	}

	return false
}

func (i *Iptables) cacheKey(item *IptablesItem) string {
	return item.dnsType + "/" + item.trueIp.String() + "/" + strconv.Itoa(item.ttl)
}
