# hysteria2
## Architecture
### Accept a connection

#### Accept a H3 stream
handle the H3, if `H3` auth passed. then process the BiStream
else return a `H3` errored resp.

#### loop accept bistream