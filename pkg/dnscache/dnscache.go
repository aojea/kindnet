
package dnscache

import (
	"net"
	"sync"
	"time"

	"k8s.io/utils/clock"
)

type ipEntry struct {
	ts  time.Time
	ips []net.IP
}

type ipCache struct {
	mu             sync.RWMutex
	clock          clock.Clock
	cacheV4Address map[string]ipEntry
	cacheV6Address map[string]ipEntry
}

func (i *ipCache) add(network string, host string, ips []net.IP) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.clock.Now()
	entry := ipEntry{
		ts:  now,
		ips: ips,
	}
	if network == "ip6" {
		i.cacheV6Address[host] = entry
		dnsCacheSize.WithLabelValues("ip6").Set(float64(len(i.cacheV6Address)))
	}
	if network == "ip4" {
		i.cacheV4Address[host] = entry
		dnsCacheSize.WithLabelValues("ip4").Set(float64(len(i.cacheV4Address)))
	}
}

func (i *ipCache) get(network string, host string) ([]net.IP, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	var entry ipEntry
	var ok bool

	if network == "ip6" {
		entry, ok = i.cacheV6Address[host]
	}
	if network == "ip4" {
		entry, ok = i.cacheV4Address[host]
	}
	if !ok {
		return nil, false
	}
	// check if the entry is still valid
	if entry.ts.Add(expireTimeout).Before(i.clock.Now()) {
		i.delete(network, host)
		return nil, false
	}
	return entry.ips, true
}

func (i *ipCache) delete(network string, host string) {
	if network == "ip6" {
		delete(i.cacheV6Address, host)
		dnsCacheSize.WithLabelValues("ip6").Set(float64(len(i.cacheV6Address)))
	}
	if network == "ip4" {
		delete(i.cacheV4Address, host)
		dnsCacheSize.WithLabelValues("ip4").Set(float64(len(i.cacheV4Address)))
	}
}

func (i *ipCache) gc() {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.clock.Now()
	for host, entry := range i.cacheV4Address {
		// check if the entry is still valid
		if entry.ts.Add(expireTimeout).Before(now) {
			i.delete("ip4", host)
		}
	}
	for host, entry := range i.cacheV6Address {
		// check if the entry is still valid
		if entry.ts.Add(expireTimeout).Before(now) {
			i.delete("ip6", host)
		}
	}
	dnsCacheSize.WithLabelValues("ip4").Set(float64(len(i.cacheV4Address)))
	dnsCacheSize.WithLabelValues("ip6").Set(float64(len(i.cacheV6Address)))
}

func newIPCache() *ipCache {
	return &ipCache{
		cacheV4Address: map[string]ipEntry{},
		cacheV6Address: map[string]ipEntry{},
		clock:          clock.RealClock{},
	}
}
