# hbase-packet-inspector

hbase-packet-inspector captures packets to/from HBase region server.

## Usage

hbase-packet-inspector can read tcpdump output files or a live capture from the
network (the latter requires root permission).

```sh
Usage:
  hbase-packet-inspector [OPTIONS] [-i INTERFACE]
  hbase-packet-inspector [OPTIONS] FILES...

Options:
  -h --help                 Show this message
  -p --port=PORT            Port to monitor (default: 16020 and 60020)
  -c --count=COUNT          Maximum number of packets to process
  -i --interface=INTERFACE  Network interface to monitor
  -v --verbose              Verbose output
```

## Example

```sh
# Reading from tcpdump output
tcpdump -s 0 -c 100000 -nn -w dump.pcap port 16020 or port 60020
./hbase-packet-inspector dump.pcap

# Reading from a live capture
sudo ./hbase-packet-inspector
```

## License

This software is licensed under the [Apache 2 license](LICENSE.txt), quoted below.

Copyright 2016 Kakao Corp. <http://www.kakaocorp.com>

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this project except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
