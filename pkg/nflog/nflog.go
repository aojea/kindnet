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

package nflog

import (
	"context"
	"fmt"
	"syscall"

	"github.com/aojea/kindnet/pkg/network"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/florianl/go-nflog/v2"
	"github.com/mdlayher/netlink"

	"k8s.io/klog/v2"
)

// Experimental: allow to log packets for troubleshooting

const (
	tableName = "kindnet-nflog"
)

func NewNFLogAgent(logLevel int) (*NFLogAgent, error) {
	return &NFLogAgent{logLevel}, nil
}

type NFLogAgent struct {
	logLevel int
}

func (n *NFLogAgent) Run(ctx context.Context) error {
	logger := klog.FromContext(ctx)

	err := n.syncRules()
	if err != nil {
		return err
	}
	config := nflog.Config{
		Group:    100,
		Copymode: nflog.CopyPacket,
		Bufsize:  128,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		return fmt.Errorf("could not open nflog socket: %v", err)
	}
	defer nf.Close()

	// Avoid receiving ENOBUFS errors.
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		return fmt.Errorf("failed to set netlink option %v: %v",
			netlink.NoENOBUFS, err)
	}

	// hook that is called for every received packet by the nflog group
	hook := func(attrs nflog.Attribute) int {
		packet, err := network.ParsePacket(*attrs.Payload)
		if err != nil {
			logger.Error(err, "Can not process packet")
			return 0
		}
		// Just print out the payload of the nflog packet
		logger.V(n.logLevel).Info("Evaluating packet", "packet", packet)
		return 0
	}

	// errFunc that is called for every error on the registered hook
	errFunc := func(e error) int {
		// Just log the error and return 0 to continue receiving packets
		klog.Infof("received error on hook: %v", e)
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.RegisterWithErrorFunc(ctx, hook, errFunc)
	if err != nil {
		return fmt.Errorf("failed to register hook function: %v", err)
	}

	// Block till the context expires
	<-ctx.Done()
	return nil
}

func (n *NFLogAgent) syncRules() error {
	klog.V(2).Info("Syncing kindnet-nflog nftables rules")
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("fastpath failure, can not start nftables:%v", err)
	}

	// add + delete + add for flushing all the table
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	nft.AddTable(table)
	nft.DelTable(table)
	nft.AddTable(table)

	chain := nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 5),
	})
	logFlags := expr.LogFlagsIPOpt + expr.LogFlagsTCPOpt + expr.LogFlagsUID
	snaplen := uint32(64)
	// Log first and last packet of each connection
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{syscall.IPPROTO_TCP}},
			&expr.Log{Flags: logFlags, Key: 0x2, Snaplen: snaplen, Group: 100},
		},
	})

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: 0x0, Register: 0x1, Data: []byte{syscall.IPPROTO_UDP}},
			&expr.Log{Flags: logFlags, Key: 0x2, Snaplen: snaplen, Group: 100},
		},
	})
	err = nft.Flush()
	if err != nil {
		return fmt.Errorf("failed to create kindnet-fastpath table: %v", err)
	}
	return nil
}

func CleanRules() {
	nft, err := nftables.New()
	if err != nil {
		klog.Infof("fastpath cleanup failure, can not start nftables:%v", err)
		return
	}
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})
	nft.DelTable(table)

	err = nft.Flush()
	if err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}
