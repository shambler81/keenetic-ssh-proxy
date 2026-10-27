package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var dataDir = "/opt/etc/ssh-proxy"
var sshBin = "/opt/bin/ssh"
var keyscanBin = "/opt/bin/ssh-keyscan"
var hostRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$`)
var userRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
var newSSHCommand = exec.CommandContext

type Config struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	Auth          string `json:"auth"`
	Password      string `json:"password,omitempty"`
	PrivateKey    string `json:"privateKey,omitempty"`
	KeyPassphrase string `json:"keyPassphrase,omitempty"`
	Certificate   string `json:"certificate,omitempty"`
	HostKey       string `json:"hostKey"`
	Fingerprint   string `json:"fingerprint"`
	SocksPort     int    `json:"socksPort"`
	Autostart     bool   `json:"autostart"`
	Reconnect     bool   `json:"reconnect"`
}

type Server struct {
	mu          sync.Mutex
	cfg         Config
	running     bool
	status      string
	lastError   string
	cancel      context.CancelFunc
	webPassword string
}

func secureWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func initData(addr string) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	passwordFile := filepath.Join(dataDir, "web-password")
	if _, err := os.Stat(passwordFile); errors.Is(err, os.ErrNotExist) {
		b := make([]byte, 24)
		if _, err = rand.Read(b); err != nil {
			return err
		}
		pass := base64.RawURLEncoding.EncodeToString(b)
		if err = secureWrite(passwordFile, []byte(pass)); err != nil {
			return err
		}
		fmt.Println("Login: admin\nWeb password: " + pass)
	}
	certFile, keyFile := filepath.Join(dataDir, "web.crt"), filepath.Join(dataDir, "web.key")
	if _, err := os.Stat(certFile); err == nil {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	t := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Keenetic SSH Proxy"}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		t.IPAddresses = append(t.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err = secureWrite(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})); err != nil {
		return err
	}
	return secureWrite(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func readConfig() Config {
	c := Config{Port: 22, SocksPort: 1080, Auth: "password", Reconnect: true}
	if b, err := os.ReadFile(filepath.Join(dataDir, "config.json")); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func keyFingerprint(key string) (string, string, error) {
	parts := strings.Fields(key)
	if len(parts) != 2 || !(strings.HasPrefix(parts[0], "ssh-") || strings.HasPrefix(parts[0], "ecdsa-") || strings.HasPrefix(parts[0], "sk-")) {
		return "", "", errors.New("Неверный открытый ключ сервера")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(raw) < 16 {
		return "", "", errors.New("Неверное содержимое ключа сервера")
	}
	sum := sha256.Sum256(raw)
	return parts[0] + " " + parts[1], "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func validate(c Config) error {
	if !hostRE.MatchString(c.Host) || !userRE.MatchString(c.User) {
		return errors.New("Проверьте адрес и имя пользователя")
	}
	if c.Port < 1 || c.Port > 65535 || c.SocksPort < 1024 || c.SocksPort > 65535 {
		return errors.New("Неверный порт")
	}
	if c.Auth != "password" && c.Auth != "key" {
		return errors.New("Выберите способ авторизации")
	}
	if c.Auth == "password" && c.Password == "" {
		return errors.New("Укажите пароль SSH")
	}
	if c.Auth == "key" && !strings.Contains(c.PrivateKey, "PRIVATE KEY-----") {
		return errors.New("Укажите закрытый ключ SSH")
	}
	_, fp, err := keyFingerprint(c.HostKey)
	if err != nil {
		return err
	}
	if fp != strings.TrimSpace(c.Fingerprint) {
		return errors.New("Отпечаток ключа не совпадает с подтверждённым")
	}
	return nil
}

func (s *Server) setStatus(status, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
	s.lastError = msg
}

func (s *Server) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("Подключение уже запущено")
	}
	if err := validate(s.cfg); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.running = true
	s.status = "connecting"
	s.lastError = ""
	c := s.cfg
	go s.run(ctx, c)
	return nil
}

func (s *Server) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.running {
		s.status = "stopping"
	}
}

func (s *Server) run(ctx context.Context, c Config) {
	defer func() { s.mu.Lock(); s.running = false; s.status = "stopped"; s.cancel = nil; s.mu.Unlock() }()
	for {
		if ctx.Err() != nil {
			return
		}
		s.setStatus("connecting", "")
		err := s.runOnce(ctx, c)
		if ctx.Err() != nil {
			return
		}
		msg := "Соединение завершено"
		if err != nil {
			msg = err.Error()
		}
		for _, secret := range []string{c.Password, c.KeyPassphrase, c.PrivateKey} {
			if secret != "" {
				msg = strings.ReplaceAll(msg, secret, "[скрыто]")
			}
		}
		if len(msg) > 700 {
			msg = msg[len(msg)-700:]
		}
		if !c.Reconnect {
			s.mu.Lock()
			s.lastError = msg
			s.mu.Unlock()
			return
		}
		s.setStatus("retrying", msg)
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func (s *Server) runOnce(ctx context.Context, c Config) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(c.SocksPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("Локальный порт %d занят: %w", c.SocksPort, err)
	}
	_ = ln.Close()
	key, _, err := keyFingerprint(c.HostKey)
	if err != nil {
		return err
	}
	knownHost := c.Host
	if c.Port != 22 {
		knownHost = fmt.Sprintf("[%s]:%d", c.Host, c.Port)
	}
	known := fmt.Sprintf("%s %s\n", knownHost, key)
	if err = secureWrite(filepath.Join(dataDir, "known_hosts"), []byte(known)); err != nil {
		return err
	}
	args := []string{"-F", "/dev/null", "-N", "-T", "-D", addr, "-p", strconv.Itoa(c.Port), "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + filepath.Join(dataDir, "known_hosts"), "-o", "GlobalKnownHostsFile=/dev/null", "-o", "NumberOfPasswordPrompts=1", "-o", "LogLevel=ERROR"}
	if c.Auth == "key" {
		if err = secureWrite(filepath.Join(dataDir, "identity"), []byte(c.PrivateKey+"\n")); err != nil {
			return err
		}
		if c.Certificate != "" {
			if err = secureWrite(filepath.Join(dataDir, "identity-cert.pub"), []byte(strings.TrimSpace(c.Certificate)+"\n")); err != nil {
				return err
			}
		} else {
			_ = os.Remove(filepath.Join(dataDir, "identity-cert.pub"))
		}
		args = append(args, "-i", filepath.Join(dataDir, "identity"), "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey")
	} else {
		args = append(args, "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no")
	}
	args = append(args, c.User+"@"+c.Host)
	cmd := newSSHCommand(ctx, sshBin, args...)
	cmd.Env = append(os.Environ(), "DISPLAY=none", "SSH_ASKPASS_REQUIRE=force", "SSH_ASKPASS="+filepath.Join(dataDir, "askpass"), "SSH_PROXY_DIR="+dataDir)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(350 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err = <-done:
			if err == nil {
				return errors.New("SSH завершился")
			}
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		case <-ctx.Done():
			<-done
			return ctx.Err()
		case <-ticker.C:
			conn, e := net.DialTimeout("tcp", addr, 250*time.Millisecond)
			if e == nil {
				_ = conn.Close()
				s.setStatus("connected", "")
			}
		}
	}
}

func (s *Server) authorize(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		a := sha256.Sum256([]byte(p))
		b := sha256.Sum256([]byte(s.webPassword))
		if !ok || u != "admin" || subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="SSH Proxy"`)
			http.Error(w, "Authentication required", 401)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		if r.Method != "GET" {
			origin := r.Header.Get("Origin")
			u, e := url.Parse(origin)
			if e != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, r.Host) {
				http.Error(w, "Invalid origin", 403)
				return
			}
		}
		h(w, r)
	}
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 128*1024)).Decode(v)
}
func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfg
	c.Password = ""
	c.PrivateKey = ""
	c.KeyPassphrase = ""
	c.Certificate = ""
	reply(w, map[string]any{"config": c, "running": s.running, "status": s.status, "error": s.lastError, "passwordSaved": s.cfg.Password != "", "keySaved": s.cfg.PrivateKey != "", "certificateSaved": s.cfg.Certificate != ""})
}
func (s *Server) saveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	var c Config
	if err := readJSON(r, &c); err != nil {
		http.Error(w, "Неверные данные", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		http.Error(w, "Сначала отключите соединение", 409)
		return
	}
	if c.Password == "" {
		c.Password = s.cfg.Password
	}
	if c.PrivateKey == "" {
		c.PrivateKey = s.cfg.PrivateKey
	}
	if c.KeyPassphrase == "" {
		c.KeyPassphrase = s.cfg.KeyPassphrase
	}
	if c.Certificate == "" {
		c.Certificate = s.cfg.Certificate
	}
	if err := validate(c); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err == nil {
		err = secureWrite(filepath.Join(dataDir, "config.json"), b)
	}
	if err != nil {
		http.Error(w, "Не удалось сохранить профиль", 500)
		return
	}
	s.cfg = c
	reply(w, map[string]bool{"ok": true})
}
func (s *Server) commandHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if readJSON(r, &req) != nil {
		http.Error(w, "data", 400)
		return
	}
	switch req.Action {
	case "start":
		if err := s.start(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	case "stop":
		s.stop()
	default:
		http.Error(w, "action", 400)
		return
	}
	reply(w, map[string]bool{"ok": true})
}

func (s *Server) scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	var req struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if readJSON(r, &req) != nil || !hostRE.MatchString(req.Host) || req.Port < 1 || req.Port > 65535 {
		http.Error(w, "Неверный адрес или порт", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 9*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, keyscanBin, "-T", "6", "-p", strconv.Itoa(req.Port), "-t", "ed25519,rsa,ecdsa", req.Host).Output()
	if err != nil {
		http.Error(w, "Не удалось получить ключ сервера", 502)
		return
	}
	var out []map[string]string
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 3 || strings.HasPrefix(parts[0], "#") {
			continue
		}
		key, fp, e := keyFingerprint(parts[1] + " " + parts[2])
		if e == nil {
			out = append(out, map[string]string{"key": key, "fingerprint": fp})
		}
	}
	if len(out) == 0 {
		http.Error(w, "Сервер не предоставил ключи", 502)
		return
	}
	reply(w, out)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--askpass" {
		dataDir = os.Getenv("SSH_PROXY_DIR")
		c := readConfig()
		if c.Auth == "key" {
			fmt.Print(c.KeyPassphrase)
		} else {
			fmt.Print(c.Password)
		}
		return
	}
	listen := flag.String("listen", "127.0.0.1:8181", "HTTPS address")
	initOnly := flag.Bool("init", false, "initialize credentials and certificate")
	flag.StringVar(&dataDir, "data", dataDir, "private data directory")
	flag.StringVar(&sshBin, "ssh", sshBin, "OpenSSH client")
	flag.StringVar(&keyscanBin, "keyscan", keyscanBin, "ssh-keyscan")
	flag.Parse()
	if *initOnly {
		if err := initData(*listen); err != nil {
			log.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "web-password"))
	if err != nil {
		log.Fatal("Run with --init first")
	}
	self, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	if strings.ContainsAny(self, "'\n\r") {
		log.Fatal("Unsupported executable path")
	}
	if err = secureWrite(filepath.Join(dataDir, "askpass"), []byte("#!/bin/sh\nexec '"+self+"' --askpass\n")); err != nil {
		log.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(dataDir, "askpass"), 0700); err != nil {
		log.Fatal(err)
	}
	s := &Server{cfg: readConfig(), status: "stopped", webPassword: strings.TrimSpace(string(b))}
	http.HandleFunc("/", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, htmlPage)
	}))
	http.HandleFunc("/api/status", s.authorize(s.statusHandler))
	http.HandleFunc("/api/save", s.authorize(s.saveHandler))
	http.HandleFunc("/api/command", s.authorize(s.commandHandler))
	http.HandleFunc("/api/scan", s.authorize(s.scanHandler))
	if s.cfg.Autostart {
		if e := s.start(); e != nil {
			log.Print(e)
		}
	}
	srv := &http.Server{Addr: *listen, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second}
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdown
		s.stop()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	err = srv.ListenAndServeTLS(filepath.Join(dataDir, "web.crt"), filepath.Join(dataDir, "web.key"))
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.stop()
		log.Fatal(err)
	}
	// Wait for OpenSSH's child process to exit before the service terminates.
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
}
