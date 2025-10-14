/*
Copyright YEAR The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dnscache

import (
	"net"
	"testing"
	"time"

	testingclock "k8s.io/utils/clock/testing"
)

func TestIPCache(t *testing.T) {
	clock := testingclock.NewFakeClock(time.Now())
	c := &ipCache{
		cacheV4Address: map[string]ipEntry{},
		cacheV6Address: map[string]ipEntry{},
		clock:          clock,
	}

	hostv4 := "host.com"
	hostv6 := "hostv6.com"
	ip4 := net.ParseIP("1.2.3.4")
	ip6 := net.ParseIP("2001:db8::1")

	// Test adding and retrieving IPv4 and IPv6 entries
	c.add("ip4", hostv4, []net.IP{ip4})
	c.add("ip6", hostv6, []net.IP{ip6})

	if ips, ok := c.get("ip4", hostv4); !ok || len(ips) != 1 || !ips[0].Equal(ip4) {
		t.Errorf("Failed to retrieve IPv4 entry")
	}
	if ips, ok := c.get("ip6", hostv6); !ok || len(ips) != 1 || !ips[0].Equal(ip6) {
		t.Errorf("Failed to retrieve IPv6 entry")
	}

	// Test retrieving non-existent entry
	if _, ok := c.get("ip4", "nonexistent.com"); ok {
		t.Errorf("Retrieved non-existent entry")
	}

	// Test deleting entries
	c.delete("ip4", hostv4)
	c.delete("ip6", hostv6)

	if _, ok := c.get("ip4", hostv4); ok {
		t.Errorf("Retrieved deleted IPv4 entry")
	}
	if _, ok := c.get("ip6", hostv6); ok {
		t.Errorf("Retrieved deleted IPv6 entry")
	}
}

func TestIPCacheGC(t *testing.T) {
	clock := testingclock.NewFakeClock(time.Now())
	c := &ipCache{
		cacheV4Address: map[string]ipEntry{},
		cacheV6Address: map[string]ipEntry{},
		clock:          clock,
	}
	host := "host.com"
	ip := net.ParseIP("1.2.3.4")

	c.add("ip4", host, []net.IP{ip})
	// Advance the clock so the entry gets expired
	clock.SetTime(clock.Now().Add(time.Hour))

	c.gc()

	if len(c.cacheV4Address) != 0 {
		t.Errorf("GC did not remove expired entry")
	}
}

func TestIPCacheGetExpire(t *testing.T) {
	clock := testingclock.NewFakeClock(time.Now())
	c := &ipCache{
		cacheV4Address: map[string]ipEntry{},
		cacheV6Address: map[string]ipEntry{},
		clock:          clock,
	}
	host := "host.com"
	ip := net.ParseIP("1.2.3.4")

	c.add("ip4", host, []net.IP{ip})
	// Advance the clock so the entry gets expired
	clock.SetTime(clock.Now().Add(time.Hour))

	if _, ok := c.get("ip4", host); ok {
		t.Errorf("GC did not remove expired entry")
	}

}
