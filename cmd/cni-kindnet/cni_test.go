// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netns"
)

func TestCNIPlugin(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatalf("Test requires root privileges.")
	}
	tests := []struct {
		name   string
		ranges []netip.Prefix
	}{
		{"ipv4", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
		{"ipv6", []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}},
		{"dual", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("2001:db8::/64")}},
	}

	for _, rt := range tests {
		t.Run(rt.name, func(t *testing.T) {
			tempDir, err := ioutil.TempDir("", "temp")
			if err != nil {
				t.Errorf("create tempDir: %v", err)
			}
			t.Logf("logs on %s", tempDir)
			dbDir = tempDir
			t.Setenv("CNI_LOG_FILE", filepath.Join(tempDir, "test.log"))
			t.Cleanup(func() { os.RemoveAll(tempDir) })

			// initialize variables
			err = start()
			if err != nil {
				t.Fatal(err)
			}
			// 1. Prepare test environment
			// Save the current network namespace
			origns, err := netns.Get()
			if err != nil {
				t.Fatalf("unexpected error trying to get namespace: %v", err)
			}
			defer origns.Close()

			nsName := "test-ns"
			testNS, err := netns.NewNamed(nsName)
			if err != nil {
				t.Fatalf("Failed to create network namespace: %v", err)
			}
			defer netns.DeleteNamed(nsName)
			defer testNS.Close()

			// Switch back to the original namespace
			netns.Set(origns)

			// 3. Prepare CNI configuration
			cniConfig := KindnetConf{
				NetConf: types.NetConf{
					CNIVersion: "0.3.1",
					Name:       "test-network",
					Type:       "cni-kindnet",
				},
			}
			for _, cidr := range rt.ranges {
				cniConfig.Ranges = append(cniConfig.Ranges, cidr.String())
			}

			data, err := json.Marshal(cniConfig)
			if err != nil {
				t.Fatalf("Failed to serialize cni config: %v", err)
			}
			//  Prepare CNI arguments
			args := &skel.CmdArgs{
				ContainerID: "test-container",
				Netns:       filepath.Join("/run/netns/", nsName),
				IfName:      "eth0",
				StdinData:   data,
			}

			//  Execute ADD command
			if err := cmdAdd(args); err != nil {
				t.Fatalf("CNI ADD command failed: %v", err)
			}

			// check connectivity from the namespace
			func() {
				err := netns.Set(testNS)
				if err != nil {
					t.Fatal(err)
				}
				// use the first IP family first network address
				cmd := exec.Command("ping", "-c", "3", rt.ranges[0].Masked().Addr().String())

				// (Optional) Get output
				_, err = cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("no connectivity from namespace: %v", err)
				}

				// Switch back to the original namespace
				err = netns.Set(origns)
				if err != nil {
					t.Fatal(err)
				}
			}()

			//  Execute DEL command
			if err := cmdDel(args); err != nil {
				t.Errorf("CNI DEL command failed: %v", err)
			}

			// TODO test check
			err = cmdCheck(args)
		})
	}
}

func TestAddDel(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatalf("Test requires root privileges.")
	}

	now := time.Now()
	total := 300
	tempDir, err := ioutil.TempDir("", "temp")
	if err != nil {
		t.Errorf("create tempDir: %v", err)
	}
	t.Logf("logs on %s", tempDir)
	dbDir = tempDir
	t.Setenv("CNI_LOG_FILE", filepath.Join(tempDir, "test.log"))
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	// initialize variables
	err = start()
	if err != nil {
		t.Fatal(err)
	}

	// Save the current network namespace
	origns, err := netns.Get()
	if err != nil {
		t.Fatalf("unexpected error trying to get namespace: %v", err)
	}
	defer origns.Close()

	var successes atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {

		runtime.LockOSThread()
		rndString := make([]byte, 4)
		_, err := rand.Read(rndString)
		if err != nil {
			t.Errorf("fail to generate random name: %v", err)
		}
		nsName := fmt.Sprintf("ns%x", rndString)
		testNS, err := netns.NewNamed(nsName)
		if err != nil {
			t.Errorf("Failed to create network namespace: %v", err)
		}
		// Switch back to the original namespace
		netns.Set(origns)
		runtime.UnlockOSThread()

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer netns.DeleteNamed(nsName)
			defer testNS.Close()

			success := true
			// Prepare CNI configuration
			cniConfig := KindnetConf{
				NetConf: types.NetConf{
					CNIVersion: "0.3.1",
					Name:       "test-network",
					Type:       "cni-kindnet",
				},
				Ranges: []string{"169.254.99.0/24"},
			}

			data, err := json.Marshal(cniConfig)
			if err != nil {
				success = false
				t.Errorf("Failed to serialize cni config: %v", err)
			}
			//  Prepare CNI arguments
			args := &skel.CmdArgs{
				ContainerID: nsName,
				Netns:       filepath.Join("/run/netns/", nsName),
				IfName:      "eth0",
				StdinData:   data,
			}

			//  Execute ADD command
			if err := cmdAdd(args); err != nil {
				success = false
				t.Errorf("CNI ADD command failed: %v", err)
			}

			//  Execute DEL command
			if err := cmdDel(args); err != nil {
				success = false
				t.Errorf("CNI DEL command failed: %v", err)
			}
			if success {
				successes.Add(1)
			}
		}()
	}
	// database should be empty at this point
	wg.Wait()
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM pods").Scan(&count)
	if err != nil {
		log.Fatal(err)
	}

	// Check if the count is zero
	if count != 0 {
		t.Errorf("The pods database is not empty: %d", count)
	} else {
		t.Logf("no pods remaining in the db")
	}
	t.Logf("%d success out of %d in %v", successes.Load(), total, time.Since(now))
}

func TestAdds(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatalf("Test requires root privileges.")
	}

	now := time.Now()
	total := 300
	tempDir, err := ioutil.TempDir("", "temp")
	if err != nil {
		t.Errorf("create tempDir: %v", err)
	}
	t.Logf("logs on %s", tempDir)
	dbDir = tempDir
	t.Setenv("CNI_LOG_FILE", filepath.Join(tempDir, "test.log"))
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	// initialize variables
	err = start()
	if err != nil {
		t.Fatal(err)
	}

	// Save the current network namespace
	origns, err := netns.Get()
	if err != nil {
		t.Fatalf("unexpected error trying to get namespace: %v", err)
	}
	defer origns.Close()

	var successes atomic.Uint64
	var wg sync.WaitGroup
	argsCh := make(chan *skel.CmdArgs, total)
	for i := 0; i < total; i++ {

		runtime.LockOSThread()
		rndString := make([]byte, 4)
		_, err := rand.Read(rndString)
		if err != nil {
			t.Errorf("fail to generate random name: %v", err)
		}
		nsName := fmt.Sprintf("ns%x", rndString)
		_, err = netns.NewNamed(nsName)
		if err != nil {
			t.Errorf("Failed to create network namespace: %v", err)
		}
		// Switch back to the original namespace
		netns.Set(origns)
		runtime.UnlockOSThread()

		wg.Add(1)
		go func() {
			defer wg.Done()

			success := true
			// Prepare CNI configuration
			cniConfig := KindnetConf{
				NetConf: types.NetConf{
					CNIVersion: "0.3.1",
					Name:       "test-network",
					Type:       "cni-kindnet",
				},
				Ranges: []string{"fd00:1:2:3::/64"},
			}

			data, err := json.Marshal(cniConfig)
			if err != nil {
				success = false
				t.Errorf("Failed to serialize cni config: %v", err)
			}
			//  Prepare CNI arguments
			args := &skel.CmdArgs{
				ContainerID: nsName,
				Netns:       filepath.Join("/run/netns/", nsName),
				IfName:      "eth0",
				StdinData:   data,
			}

			//  Execute ADD command
			if err := cmdAdd(args); err != nil {
				success = false
				t.Errorf("CNI ADD command failed: %v", err)
			}

			if success {
				successes.Add(1)
			}
			argsCh <- args
		}()
	}
	// database should be empty at this point
	wg.Wait()
	t.Logf("%d success added out of %d in %v", successes.Load(), total, time.Since(now))

	for i := 0; i < total; i++ {
		args := <-argsCh
		wg.Add(1)
		go func() {
			defer wg.Done()
			//  Execute DEL command
			if err := cmdDel(args); err != nil {
				t.Errorf("CNI DEL command failed: %v", err)
			}
			netns.DeleteNamed(filepath.Base(args.Netns))
		}()
	}

	wg.Wait()
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM pods").Scan(&count)
	if err != nil {
		log.Fatal(err)
	}

	// Check if the count is zero
	if count != 0 {
		t.Errorf("The pods database is not empty: %d", count)
	} else {
		t.Logf("no pods remaining in the db")
	}
	t.Logf("%d success out of %d in %v", successes.Load(), total, time.Since(now))
}
