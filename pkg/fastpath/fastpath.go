// SPDX-License-Identifier: APACHE-2.0

package fastpath

import (
	"context"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"sigs.k8s.io/knftables"
)

const (
	kindnetFlowtable = "kindnet-flowtables"
	fastPathChain    = "kindnet-fastpath-chain"
)

func NewFastpathAgent(packetThresold int) (*FastPathAgent, error) {
	klog.V(2).Info("Initializing nftables")
	nft, err := knftables.New(knftables.InetFamily, "kindnet-fastpath")
	if err != nil {
		return nil, err
	}
	return &FastPathAgent{
		nft:            nft,
		packetThresold: packetThresold,
	}, nil
}

type FastPathAgent struct {
	nft            knftables.Interface
	packetThresold int
}

func (ma *FastPathAgent) Run(ctx context.Context) error {
	klog.Info("Syncing nftables rules")
	table := &knftables.Table{
		Comment: knftables.PtrTo("rules for kindnet fastpath"),
	}
	tx := ma.nft.NewTransaction()
	// do it once to delete the existing table
	tx.Add(table)
	tx.Delete(table)
	tx.Add(table)

	tx.Add(&knftables.Flowtable{
		Name: kindnetFlowtable,
	})

	tx.Add(&knftables.Chain{
		Name:     fastPathChain,
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.ForwardHook),
		Priority: knftables.PtrTo(knftables.DNATPriority + "-10"),
	})

	tx.Add(&knftables.Rule{
		Chain: fastPathChain,
		Rule: knftables.Concat(
			"ct packets >", ma.packetThresold,
			"flow offload", "@", kindnetFlowtable,
			"counter",
		),
	})

	err := ma.nft.Run(ctx, tx)
	if err != nil {
		klog.Error(err, "failed to add network interfaces to the flowtable")
	}

	minInterval := 5 * time.Second
	maxInterval := 1 * time.Minute
	rateLimiter := rate.NewLimiter(rate.Every(minInterval), 1)
	// Resources are published periodically or if there is a netlink notification
	// indicating a new interfaces was added or changed
	nlChannel := make(chan netlink.LinkUpdate)
	doneCh := make(chan struct{})
	defer close(doneCh)
	if err := netlink.LinkSubscribe(nlChannel, doneCh); err != nil {
		klog.Error(err, "error subscribing to netlink interfaces, only syncing periodically", "interval", maxInterval.String())
	}

	currentIf := sets.Set[string]{}
	for {
		err := rateLimiter.Wait(ctx)
		if err != nil {
			klog.Error(err, "unexpected rate limited error trying to get system interfaces")
		}
		ifnames, err := ma.getNodeInterfaces()
		if err != nil {
			klog.Error(err, "failed to list system network interfaces")
		}

		if len(ifnames) > 0 && !ifnames.Equal(currentIf) {
			tx := ma.nft.NewTransaction()
			tx.Add(&knftables.Flowtable{
				Name:    kindnetFlowtable,
				Devices: ifnames.UnsortedList(),
			})
			err := ma.nft.Run(ctx, tx)
			if err != nil {
				klog.Error(err, "failed to add network interfaces to the flowtable")
			} else {
				currentIf = ifnames
			}
		}

		select {
		// trigger a reconcile
		case <-nlChannel:
			// drain the channel so we only sync once
			for len(nlChannel) > 0 {
				<-nlChannel
			}
		case <-time.After(maxInterval):
		case <-ctx.Done():
			return nil
		}
	}
}

func (ma *FastPathAgent) getNodeInterfaces() (sets.Set[string], error) {
	ifNames := sets.New[string]()

	links, err := netlink.LinkList()
	if err != nil {
		return ifNames, err
	}

	for _, link := range links {
		klog.V(7).InfoS("Checking network interface", "name", link.Attrs().Name)
		// skip down interfaces
		if link.Attrs().OperState != netlink.OperUp {
			continue
		}
		// skip loopback interfaces
		if link.Attrs().Flags&net.FlagLoopback != 0 {
			continue
		}

		klog.V(7).InfoS("Checking network interface", "name", link.Attrs().Name)
		ifNames.Insert(link.Attrs().Name)
	}
	return ifNames, nil
}

func (ma *FastPathAgent) CleanRules() {
	tx := ma.nft.NewTransaction()
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	tx.Add(&knftables.Table{})
	tx.Delete(&knftables.Table{})

	if err := ma.nft.Run(context.TODO(), tx); err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}
