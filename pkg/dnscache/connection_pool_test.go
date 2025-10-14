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
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// === RUN   TestConnectionPoolIntegration: connection_pool_test.go:103: 5000 requests with 3 connections in 103.187534ms
func TestConnectionPoolIntegration(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener, %v", err)
	}
	defer listener.Close()

	var numConnections atomic.Int32
	var numRequest atomic.Int32

	go func() {
		// listen for new connections
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			numConnections.Add(1)
			// pass an accepted connection to a handler goroutine
			go func() {
				reader := bufio.NewReader(conn)
				for {
					// read client request data
					msg, err := reader.ReadString('\n')
					if err != nil {
						if err != io.EOF {
							t.Errorf("failed to read data, %v", err)
						}
						return
					}
					numRequest.Add(1)
					// prepend prefix and send as response
					line := fmt.Sprintf("pong %s\n", msg)
					conn.Write([]byte(line))
				}
			}()
		}
	}()

	// Create a connection pool with a small capacity
	pools := NewPools()
	pool := pools.Get(listener.Addr().String())

	// Send multiple DNS requests
	var wg sync.WaitGroup
	total := 5000
	start := time.Now()
	for i := 0; i < total; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			c, err := pool.Get()
			if err != nil {
				t.Errorf("Error getting connection: %v", err)
				return
			}
			defer pool.Put(c)

			c.Write([]byte("ping\n"))

			reader := bufio.NewReader(c)
			msg, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					t.Errorf("failed to read data, %v", err)
				}
				return
			}
			if !strings.Contains(msg, "pong") {
				t.Errorf("unexpected message: %s", msg)
			}
		}()
	}

	wg.Wait()

	if int(numConnections.Load()) != capacity {
		t.Errorf("Expected %d connections to the test server, got %d", capacity, numConnections.Load())
	}

	if int(numRequest.Load()) != total {
		t.Errorf("Expected %d requests to the test server, got %d", total, numRequest.Load())
	}

	t.Logf("%d requests with %d connections in %v", total, capacity, time.Since(start))
}
