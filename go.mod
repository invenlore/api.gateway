module github.com/invenlore/api.gateway

go 1.24.12

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/invenlore/core v0.3.1
	github.com/invenlore/proto v1.4.8
	github.com/prometheus/client_golang v1.23.2
	github.com/sirupsen/logrus v1.9.4
	google.golang.org/grpc v1.78.0
)

require golang.org/x/sync v0.19.0

require go.mongodb.org/mongo-driver v1.17.9 // indirect

require (
	github.com/alexliesenfeld/health v0.8.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/caarlos0/env/v11 v11.3.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/google/uuid v1.6.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.7
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260203192932-546029d2fa20 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260203192932-546029d2fa20
	google.golang.org/protobuf v1.36.11
)
