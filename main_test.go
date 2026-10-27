package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sampleConfig(t *testing.T) Config {
	t.Helper()
	key := "ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte("not-an-actual-ssh-server-key-but-long-enough"))
	_, fp, err := keyFingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Host: "ssh.example.test", Port: 22, User: "user", Auth: "password", Password: "keep secret", HostKey: key, Fingerprint: fp, SocksPort: 1080, Reconnect: true}
}

func TestValidateRejectsInjectionAndMismatchedKeys(t *testing.T) {
	c := sampleConfig(t)
	if err := validate(c); err != nil {
		t.Fatal(err)
	}
	c.Host = "example.com -oProxyCommand=evil"
	if validate(c) == nil {
		t.Fatal("malicious hostname accepted")
	}
	c = sampleConfig(t)
	c.Fingerprint = "SHA256:wrong"
	if validate(c) == nil {
		t.Fatal("wrong host fingerprint accepted")
	}
	c = sampleConfig(t)
	c.SocksPort = 22
	if validate(c) == nil {
		t.Fatal("privileged SOCKS port accepted")
	}
}

func TestAPIProtectsSecretsAndRequiresOrigin(t *testing.T) {
	old := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = old }()
	s := &Server{cfg: sampleConfig(t), status: "stopped", webPassword: "test-web-password"}
	req := httptest.NewRequest(http.MethodGet, "https://router.test/api/status", nil)
	rr := httptest.NewRecorder()
	s.authorize(s.statusHandler)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request: %d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "https://router.test/api/status", nil)
	req.SetBasicAuth("admin", s.webPassword)
	rr = httptest.NewRecorder()
	s.authorize(s.statusHandler)(rr, req)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), s.cfg.Password) {
		t.Fatalf("status response leaked secret: %s", rr.Body.String())
	}
	c := s.cfg
	c.Password = ""
	b, _ := json.Marshal(c)
	req = httptest.NewRequest(http.MethodPost, "https://router.test/api/save", bytes.NewReader(b))
	req.SetBasicAuth("admin", s.webPassword)
	req.Header.Set("Origin", "https://evil.test")
	rr = httptest.NewRecorder()
	s.authorize(s.saveHandler)(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin save accepted: %d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "https://router.test/api/save", bytes.NewReader(b))
	req.SetBasicAuth("admin", s.webPassword)
	req.Header.Set("Origin", "https://router.test")
	rr = httptest.NewRecorder()
	s.authorize(s.saveHandler)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save failed: %s", rr.Body.String())
	}
	if s.cfg.Password != "keep secret" {
		t.Fatal("empty password did not preserve saved secret")
	}
	info, err := os.Stat(filepath.Join(dataDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("config permissions too broad: %o", info.Mode().Perm())
	}
}

func TestWebBootstrap(t *testing.T) {
	old := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = old }()
	if err := initData("127.0.0.1:8181"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web-password", "web.crt", "web.key"} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// The child process stands in for OpenSSH so the supervisor is exercised with a real socket and process.
func TestSSHHelper(t *testing.T) {
	if os.Getenv("SSH_PROXY_TEST_HELPER") != "yes" {
		return
	}
	args := os.Args
	addr := ""
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-D" {
			addr = args[i+1]
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		os.Exit(2)
	}
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(3)
		}
		_ = c.Close()
	}
}

func TestSupervisorStartsAndStopsProxyProcess(t *testing.T) {
	oldDir, oldSSH, oldFactory := dataDir, sshBin, newSSHCommand
	defer func() { dataDir = oldDir; sshBin = oldSSH; newSSHCommand = oldFactory }()
	dataDir = t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	newSSHCommand = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, binary, append([]string{"-test.run=TestSSHHelper", "--"}, args...)...)
		return cmd
	}
	t.Setenv("SSH_PROXY_TEST_HELPER", "yes")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	c := sampleConfig(t)
	c.SocksPort = port
	c.Reconnect = false
	s := &Server{cfg: c, status: "stopped"}
	if err := s.start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		s.mu.Lock()
		status := s.status
		msg := s.lastError
		s.mu.Unlock()
		if status == "connected" {
			break
		}
		if time.Now().After(deadline) {
			s.stop()
			t.Fatalf("did not connect: %s %s", status, msg)
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.stop()
	deadline = time.Now().Add(8 * time.Second)
	for {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("process did not stop")
		}
		time.Sleep(50 * time.Millisecond)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		t.Fatalf("SOCKS port still in use: %v", err)
	}
	_ = ln.Close()
}
