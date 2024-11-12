## hyper-log

Provides a http interface to aggregate many [tcp-changes](https://github.com/wavey-ai/tcp-changes) feeds into a single NL delimited changes feed using a push model.

The http1.1 service uses chunked transfer encoding for a continuous real-time feed that can be viewed in the browser or via curl (think CouchDB _changes). h1 chunked encoding is very high throughput. 

There is also a h3 service that uses `text/event-stream` (this might have slightly lower throughput but might be more suitable for many smaller messages).

The h3 service can be accessed directly with curl built for h3 (eg, `curl --http3 https://local.wavey.io:4433`) but probably requires a SRV DNS record for use in browser (although alt-srv headers are provided the browser may not use the h3 service on subsequent connections).

See [src/main.rs](src/main.rs) for a usage example that uses DNS service discovery to find new tcp servers to connect to.

### TODOS

This is a WIP and not yet fully tested.
