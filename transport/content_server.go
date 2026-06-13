package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

type contentAnnouncement struct {
	BaseURL         string `json:"base_url"`
	PID             int    `json:"pid"`
	IdentitySHA256  string `json:"identity_sha256"`
	SignatureSHA256 string `json:"signature_sha256"`
}

func ServeContentProcess(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	serverArgs := argsAfterSeparator(args)
	if len(serverArgs) == 0 || serverArgs[0] != "content-serve" {
		return fmt.Errorf("content-serve command is required")
	}
	flags := flag.NewFlagSet("content-serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var filePath, contentRef, bindHost string
	flags.StringVar(&filePath, "file", "", "content file to serve")
	flags.StringVar(&contentRef, "content-ref", "", "content ref")
	flags.StringVar(&bindHost, "bind", "127.0.0.1", "bind host")
	if err := flags.Parse(serverArgs[1:]); err != nil {
		return err
	}
	if filePath == "" || contentRef == "" {
		return fmt.Errorf("file and content-ref are required")
	}
	payload, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	identity := digestBytes(pub)
	signature := ed25519.Sign(priv, []byte(contentRef+":"+identity))
	listener, err := net.Listen("tcp", net.JoinHostPort(bindHost, "0"))
	if err != nil {
		return err
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/content", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	})
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	announcement := contentAnnouncement{
		BaseURL:         "http://" + listener.Addr().String(),
		PID:             os.Getpid(),
		IdentitySHA256:  identity,
		SignatureSHA256: digestBytes(signature),
	}
	encoded, err := json.Marshal(announcement)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, string(encoded)); err != nil {
		return err
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		_ = server.Close()
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func argsAfterSeparator(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			if i+1 >= len(args) {
				return nil
			}
			return args[i+1:]
		}
	}
	if len(args) <= 1 {
		return nil
	}
	return args[1:]
}
