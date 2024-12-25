module cni-kindnet

go 1.23.4

require (
	github.com/containernetworking/cni v1.2.3
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/vishvananda/netlink v1.3.0
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sys v0.28.0
	k8s.io/apimachinery v0.32.0
	k8s.io/utils v0.0.0-20241210054802-24370beab758
	sigs.k8s.io/knftables v0.0.18
)
