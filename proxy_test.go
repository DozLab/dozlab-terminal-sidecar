package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeVM is an SSH server that accepts anyone and, for a shell with a terminal, echoes each
// line back as "got:<line>". It reports every window size the client asks for.
func fakeVM(t *testing.T, sizes chan<- [2]uint32) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := ssh.NewServerConn(nc, config)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			ch, chReqs, err := newCh.Accept()
			if err != nil {
				return
			}
			go func() {
				for req := range chReqs {
					switch req.Type {
					case "pty-req":
						// string TERM, then uint32 cols, uint32 rows
						n := binary.BigEndian.Uint32(req.Payload)
						p := req.Payload[4+n:]
						sizes <- [2]uint32{binary.BigEndian.Uint32(p), binary.BigEndian.Uint32(p[4:])}
					case "window-change":
						sizes <- [2]uint32{binary.BigEndian.Uint32(req.Payload), binary.BigEndian.Uint32(req.Payload[4:])}
					}
					if req.WantReply {
						req.Reply(true, nil)
					}
				}
			}()
			go func() {
				lines := bufio.NewScanner(ch)
				for lines.Scan() {
					ch.Write([]byte("got:" + lines.Text() + "\n"))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestStartVMShell(t *testing.T) {
	sizes := make(chan [2]uint32, 4)
	addr := fakeVM(t, sizes)

	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	session := &TerminalSession{ID: "s1", SSHConn: conn}
	if err := startVMShell(session); err != nil {
		t.Fatalf("startVMShell: %v", err)
	}
	if got := <-sizes; got != [2]uint32{80, 24} {
		t.Errorf("pty size = %v, want cols 80, rows 24", got)
	}

	// What the browser types reaches the VM's shell, and its output comes back
	if _, err := session.input().Write([]byte("hello\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(session.output()).ReadString('\n')
	if err != nil || line != "got:hello\n" {
		t.Errorf("output = %q, %v; want %q", line, err, "got:hello\n")
	}

	if err := session.resize(120, 40); err != nil {
		t.Fatalf("resize: %v", err)
	}
	if got := <-sizes; got != [2]uint32{120, 40} {
		t.Errorf("resized to %v, want cols 120, rows 40", got)
	}

	// Closing the session ends the read, as when the browser disconnects
	p := &VMTerminalProxy{sessions: map[string]*TerminalSession{"s1": session}}
	p.cleanupSession("s1")
	if _, err := session.output().Read(make([]byte, 1)); err == nil {
		t.Error("read after cleanup succeeded, want an error")
	}
	if len(p.sessions) != 0 {
		t.Errorf("sessions after cleanup = %d, want 0", len(p.sessions))
	}
}
