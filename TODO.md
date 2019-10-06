- Why Dev? - _Named it dev since the current custom dns solution is kinda hacked and is more targed at development and testing... Guessing this is the wrong design methodology?_

- https://godoc.org/github.com/CS-5/exfil2dns#Client.Encode
It's usually a good idea to not call log.Anything from libraries.  People sometimes have their own logging setup.
If the problem is really, really bad, maybe panic(), though that's usually only useful for out of memory errors and similar non-recoverable things.
Even running out of entropy and not getting random numbers may be recoverable.
Though, any reason to expose that to users in the first place?

_I was origionally going to keep Encode and Send unexported since there's not really any point in a user calling them directly when they can just call exfil. I exported them more for the sake of the talk (If someone goes to the GoDoc, they can see the breakdown of the functionality to a degree). Thoughts on this ideology?_ 

- https://github.com/CS-5/exfil2dns/blob/master/exfil2dns.go#L204
I'd avoid this unless Go's error messages when packets sent suck less than they did a while back.
Used to happen if the DNS query failed it'd still give you the IP address of the default resolver.

_Agreed. That is exactly what I discovered when testing, but I was split at either: Preventing users from specifying a custom DNS server all together, or writing a long and complexish DNS query function which seemed to exceed the scope of this library. It's for this reason that usage of the custom DialContext is resticted to NewDevClient (See my "Why Dev?" explination above)_