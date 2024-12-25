// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/knftables"
)

func getPortMapEntries() ([]PortMapConfig, error) {
	rows, err := db.Query(`
		SELECT host_ip, host_port, protocol, container_ip, container_port 
		FROM portmap_entries
	`)
	if err != nil {
		return nil, fmt.Errorf("error querying port map entries: %w", err)
	}
	defer rows.Close()

	var entries []PortMapConfig
	for rows.Next() {
		var entry PortMapConfig
		err := rows.Scan(
			&entry.HostIP, &entry.HostPort, &entry.Protocol,
			&entry.ContainerIP, &entry.ContainerPort,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning port map entry: %w", err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// reconcilePortMaps gets all the existing portmaps from the database
// and reconfigures all the nftables with the db state
func reconcilePortMaps() error {
	entries, err := getPortMapEntries()
	if err != nil {
		return err
	}
	// Write nftables for the portmap functionality
	nft, err := knftables.New(knftables.InetFamily, pluginName)
	if err != nil {
		return fmt.Errorf("portmap failure, can not start nftables:%v", err)
	}

	tx := nft.NewTransaction()

	tx.Add(&knftables.Table{
		Comment: ptr.To("rules for hostports"),
	})
	tx.Flush(&knftables.Table{})

	tx.Add(&knftables.Map{
		Name:  hostPortMapv4,
		Type:  "ipv4_addr . inet_proto . inet_service : ipv4_addr . inet_service",
		Flags: []knftables.SetFlag{knftables.IntervalFlag},
	})
	tx.Flush(&knftables.Map{
		Name: hostPortMapv4},
	)
	/* Workaround to https://www.spinics.net/lists/netfilter/msg61976.html
	tx.Add(&knftables.Map{
		Name:  hostPortMapv6,
		Type:  "ipv6_addr . inet_proto . inet_service : ipv6_addr . inet_service",
		Flags: []knftables.SetFlag{knftables.IntervalFlag},
	})
	tx.Flush(&knftables.Map{
		Name: hostPortMapv6},
	)
	*/

	tx.Add(&knftables.Map{
		Name:  hostPortMapv6 + "-tcp",
		Type:  "ipv6_addr . inet_service : ipv6_addr . inet_service",
		Flags: []knftables.SetFlag{knftables.IntervalFlag},
	})
	tx.Flush(&knftables.Map{
		Name: hostPortMapv6 + "-tcp"},
	)
	tx.Add(&knftables.Map{
		Name:  hostPortMapv6 + "-udp",
		Type:  "ipv6_addr . inet_service : ipv6_addr . inet_service",
		Flags: []knftables.SetFlag{knftables.IntervalFlag},
	})
	tx.Flush(&knftables.Map{
		Name: hostPortMapv6 + "-udp"},
	)

	tx.Add(&knftables.Chain{
		Name:     "prerouting",
		Type:     knftables.PtrTo(knftables.NATType),
		Hook:     knftables.PtrTo(knftables.PreroutingHook),
		Priority: knftables.PtrTo(knftables.DNATPriority),
	})
	tx.Add(&knftables.Rule{
		Chain: "prerouting",
		Rule:  "dnat ip to ip daddr . ip protocol . th dport map @" + hostPortMapv4,
	})

	/*
		tx.Add(&knftables.Rule{
			Chain: "prerouting",
			Rule:  "dnat to ip6 daddr . meta l4proto . th dport map @" + hostPortMapv6,
		})
	*/

	tx.Add(&knftables.Rule{
		Chain: "prerouting",
		Rule:  "dnat ip6 to ip6 daddr . tcp dport map @" + hostPortMapv6 + "-tcp",
	})
	tx.Add(&knftables.Rule{
		Chain: "prerouting",
		Rule:  "dnat ip6 to ip6 daddr . udp dport map @" + hostPortMapv6 + "-udp",
	})

	tx.Add(&knftables.Chain{
		Name:     "output",
		Type:     knftables.PtrTo(knftables.NATType),
		Hook:     knftables.PtrTo(knftables.OutputHook),
		Priority: knftables.PtrTo(knftables.DNATPriority),
	})
	tx.Add(&knftables.Rule{
		Chain: "output",
		Rule:  "meta oifname != lo return",
	})

	tx.Add(&knftables.Rule{
		Chain: "output",
		Rule:  "dnat ip to ip daddr . ip protocol . th dport map @" + hostPortMapv4,
	})

	/*
		tx.Add(&knftables.Rule{
			Chain: "output",
			Rule:  "dnat to ip6 daddr . meta l4proto . th dport map @" + hostPortMapv6,
		})
	*/
	tx.Add(&knftables.Rule{
		Chain: "output",
		Rule:  "dnat ip6 to ip6 daddr . tcp dport map @" + hostPortMapv6 + "-tcp",
	})
	tx.Add(&knftables.Rule{
		Chain: "output",
		Rule:  "dnat ip6 to ip6 daddr . udp dport map @" + hostPortMapv6 + "-udp",
	})

	// Set up this container
	for _, e := range entries {
		ip, err := netip.ParseAddr(e.ContainerIP)
		if err != nil {
			continue
		}

		if ip.Is4() {
			tx.Add(&knftables.Element{
				Map:   hostPortMapv4,
				Key:   []string{e.HostIP, e.Protocol, strconv.Itoa(e.HostPort)},
				Value: []string{e.ContainerIP, strconv.Itoa(e.ContainerPort)},
			})
		} else if ip.Is6() {
			/*
				tx.Add(&knftables.Element{
					Map:   hostPortMapv6,
					Key:   []string{e.HostIP, e.Protocol, strconv.Itoa(e.HostPort)},
					Value: []string{e.ContainerIP, strconv.Itoa(e.ContainerPort)},
				})
			*/
			if strings.ToLower(e.Protocol) == "tcp" {
				tx.Add(&knftables.Element{
					Map:   hostPortMapv6 + "-tcp",
					Key:   []string{e.HostIP, strconv.Itoa(e.HostPort)},
					Value: []string{e.ContainerIP, strconv.Itoa(e.ContainerPort)},
				})
			}
			if strings.ToLower(e.Protocol) == "udp" {
				tx.Add(&knftables.Element{
					Map:   hostPortMapv6 + "-udp",
					Key:   []string{e.HostIP, strconv.Itoa(e.HostPort)},
					Value: []string{e.ContainerIP, strconv.Itoa(e.ContainerPort)},
				})
			}
		}
	}

	err = nft.Run(context.Background(), tx)
	if err != nil {
		return fmt.Errorf("failed to add nftables for portmaps %s: %v", tx.String(), err)
	}
	return nil
}
