module github.com/MogRex-Limited/wardn/store/mongo

go 1.26.0

toolchain go1.27.3

require github.com/MogRex-Limited/wardn v1.0.0

require (
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/xdg-go/scram v1.4.0 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	go.mongodb.org/mongo-driver/v2 v2.10.0
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

// Until wardn's first tagged release, this module builds against the wardn
// in this repository. Release tagging replaces this (docs/MAINTAINING.md).
replace github.com/MogRex-Limited/wardn => ../..
