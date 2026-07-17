module quicdiver

go 1.26.3

require (
	github.com/quic-go/connect-ip-go v0.1.0
	github.com/quic-go/quic-go v0.60.0
	github.com/yosida95/uritemplate/v3 v3.0.2
	golang.org/x/net v0.56.0
	golang.org/x/sys v0.46.0
	gvisor.dev/gvisor v0.0.0-20231104011432-48a6d7d5bd0b
)

require (
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	modernc.org/libc v1.74.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.54.0 // indirect
)

replace github.com/quic-go/quic-go => ./third_party/quic-go
