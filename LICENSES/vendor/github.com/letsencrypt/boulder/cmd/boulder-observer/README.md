# boulder-observer

A modular configuration driven approach to black box monitoring with
Prometheus.

* [boulder-observer](#boulder-observer)
  * [Usage](#usage)
    * [Options](#options)
    * [Starting the boulder-observer
      daemon](#starting-the-boulder-observer-daemon)
  * [Configuration](#configuration)
    * [Root](#root)
      * [Schema](#schema)
      * [Example](#example)
    * [Monitors](#monitors)
      * [Schema](#schema-1)
      * [Example](#example-1)
    * [Probers](#probers)
      * [DNS](#dns)
        * [Schema](#schema-2)
        * [Example](#example-2)
      * [HTTP](#http)
        * [Schema](#schema-3)
        * [Example](#example-3)
  * [Metrics](#metrics)
    * [obs_monitors](#obs_monitors)
    * [obs_observations](#obs_observations)
  * [Development](#development)
    * [Starting Prometheus locally](#starting-prometheus-locally)
    * [Viewing metrics locally](#viewing-metrics-locally)

## Usage

### Options

```shell
$ ./boulder-observer -help
  -config string
        Path to boulder-observer configuration file (default "config.yml")
```

### Starting the boulder-observer daemon

```shell
$ ./boulder-observer -config test/config-next/observer.yml
I152525 boulder-observer _KzylQI Versions: main=(Unspecified Unspecified) Golang=(go1.16.2) BuildHost=(Unspecified)
I152525 boulder-observer q_D84gk Initializing boulder-observer daemon from config: test/config-next/observer.yml
I152525 boulder-observer 7aq68AQ all monitors passed validation
I152527 boulder-observer yaefiAw kind=[HTTP] success=[true] duration=[0.130097] name=[https://letsencrypt.org-[200]]
I152527 boulder-observer 65CuDAA kind=[HTTP] success=[true] duration=[0.148633] name=[http://letsencrypt.org/foo-[200 404]]
I152530 boulder-observer idi4rwE kind=[DNS] success=[false] duration=[0.000093] name=[[2606:4700:4700::1111]:53-udp-A-google.com-recurse]
I152530 boulder-observer prOnrw8 kind=[DNS] success=[false] duration=[0.000242] name=[[2606:4700:4700::1111]:53-tcp-A-google.com-recurse]
I152530 boulder-observer 6uXugQw kind=[DNS] success=[true] duration=[0.022962] name=[1.1.1.1:53-udp-A-google.com-recurse]
I152530 boulder-observer to7h-wo kind=[DNS] success=[true] duration=[0.029860] name=[owen.ns.cloudflare.com:53-udp-A-letsencrypt.org-no-recurse]
I152530 boulder-observer ovDorAY kind=[DNS] success=[true] duration=[0.033820] name=[owen.ns.cloudflare.com:53-tcp-A-letsencrypt.org-no-recurse]
...
```

## Configuration

Configuration is provided via a YAML file.

### Root

#### Schema

`debugaddr`: The Prometheus scrape port prefixed with a single colon
(e.g. `:8040`).

`buckets`: List of floats representing Prometheus histogram buckets (e.g
`[.001, .002, .005, .01, .02, .05, .1, .2, .5, 1, 2, 5, 10]`)

`syslog`: Map of log levels, see schema below.

- `stdoutlevel`: Log level for stdout, see legend below.
- `sysloglevel`:Log level for stdout, see legend below.

`0`: *EMERG* `1`: *ALERT* `2`: *CRIT* `3`: *ERR* `4`: *WARN* `5`:
*NOTICE* `6`: *INFO* `7`: *DEBUG*

`monitors`: List of monitors, see [monitors](#monitors) for schema.

#### Example

```yaml
debugaddr: :8040
buckets: [.001, .002, .005, .01, .02, .05, .1, .2, .5, 1, 2, 5, 10]
syslog:
  stdoutlevel: 6
  sysloglevel: 6
  -
    ...
```

### Monitors

#### Schema

`period`: Interval between probing attempts (e.g. `1s` `1m` `1h`).

`kind`: Kind of prober to use, see [probers](#probers) for schema.

`settings`: Map of prober settings, see [probers](#probers) for schema.

#### Example

```yaml
monitors:
  - 
    period: 5s
    kind: DNS
    settings:
        ...
```

### Probers

#### DNS

##### Schema

`protocol`: Protocol to use, options are: `udp` or `tcp`.

`server`: Hostname, IPv4 address, or IPv6 address surrounded with
brackets + port of the DNS server to send the query to (e.g.
`example.com:53`, `1.1.1.1:53`, or `[2606:4700:4700::1111]:53`).

`recurse`: Bool indicating if recursive resolution is desired.

`query_name`: Name to query (e.g. `example.com`).

`query_type`: Record type to query, options are: `A`, `AAAA`, `TXT`, or
`CAA`.

##### Example

```yaml
monitors:
  - 
    period: 5s
    kind: DNS
    settings:
      protocol: tcp
      server: [2606:4700:4700::1111]:53
      recurse: false
      query_name: letsencrypt.org
      query_type: A
```

#### HTTP

##### Schema

`url`: Scheme + Hostname to send a request to (e.g.
`https://example.com`).

`rcodes`: List of expected HTTP response codes.

`useragent`: String to set HTTP header User-Agent. If no useragent string
is provided it will default to `letsencrypt/boulder-observer-http-client`.

##### Example

```yaml
monitors:
  - 
    period: 2s
    kind: HTTP
    settings: 
      url: http://letsencrypt.org/FOO
      rcodes: [200, 404]
      useragent: letsencrypt/boulder-observer-http-client
```

## Metrics

Observer provides the following metrics.

### obs_monitors

Count of configured monitors.

**Labels:**

`kind`: Kind of Prober the monitor is configured to use.

`valid`: Bool indicating whether settings provided could be validated
for the `kind` of Prober specified.

### obs_observations

**Labels:**

`name`: Name of the monitor.

`kind`: Kind of prober the monitor is configured to use.

`duration`: Duration of the probing in seconds.

`success`: Bool indicating whether the result of the probe attempt was
successful.

**Bucketed response times:**

This is configurable, see `buckets` under [root/schema](#schema).

## Development

### Starting Prometheus locally

Please note, this assumes you've installed a local Prometheus binary.

```shell
prometheus --config.file=boulder/test/prometheus/prometheus.yml
```

### Viewing metrics locally

When developing with a local Prometheus instance you can use this link
to view metrics: [link](http://0.0.0.0:9090)