package transport

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/core/pkg/config"
	common_v1 "github.com/invenlore/proto/pkg/common/v1"
	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
	media_v1 "github.com/invenlore/proto/pkg/media/v1"
	search_v1 "github.com/invenlore/proto/pkg/search/v1"
	wiki_v1 "github.com/invenlore/proto/pkg/wiki/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ServiceConnectionInfo struct {
	Config        *config.GRPCService
	Mux           *runtime.ServeMux
	Conn          *grpc.ClientConn
	Cancel        context.CancelFunc
	Registered    bool
	HealthTimeout time.Duration

	mu sync.RWMutex
}

func (sci *ServiceConnectionInfo) Close() {
	if sci.Cancel != nil {
		sci.Cancel()
	}

	sci.mu.Lock()

	conn := sci.Conn
	sci.Conn = nil
	sci.Registered = false

	sci.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
}

func (sci *ServiceConnectionInfo) dropConn(conn *grpc.ClientConn) {
	sci.mu.Lock()

	if sci.Conn == conn {
		sci.Conn = nil
		sci.Registered = false
	}

	sci.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
}

func (sci *ServiceConnectionInfo) StartHealthCheck(ctx context.Context, dialOpts []grpc.DialOption) {
	loggerEntry := logrus.WithField("scope", "grpcServiceConnection")

	healthCtx, cancel := context.WithCancel(ctx)
	sci.Cancel = cancel

	go func(serviceCfg *config.GRPCService, mux *runtime.ServeMux) {
		ticker := time.NewTicker(sci.HealthTimeout)
		defer ticker.Stop()

		for {
			select {
			case <-healthCtx.Done():
				loggerEntry.Tracef(
					"health check for service %s stopped due to context cancellation",
					serviceCfg.Name,
				)

				return
			default:
			}

			sci.mu.RLock()

			conn := sci.Conn
			registered := sci.Registered

			sci.mu.RUnlock()

			if conn == nil {
				loggerEntry.Tracef(
					"attempting to dial gRPC service %s at %s...",
					serviceCfg.Name,
					serviceCfg.Address,
				)

				newConn, err := grpc.NewClient(serviceCfg.Address, dialOpts...)
				if err != nil {
					loggerEntry.Errorf(
						"failed to dial gRPC service %s at %s: %v",
						serviceCfg.Name,
						serviceCfg.Address,
						err,
					)

					select {
					case <-healthCtx.Done():
						return
					case <-ticker.C:
						continue
					}
				}

				sci.mu.Lock()

				if sci.Conn == nil {
					sci.Conn = newConn
					conn = newConn
				}

				sci.mu.Unlock()

				if conn != newConn {
					_ = newConn.Close()
				}
			}

			checkCtx, checkCancel := context.WithTimeout(healthCtx, 5*time.Second)
			var healthErr error

			// All microservices here
			switch serviceCfg.Name {
			case "IdentityService":
				client := identity_v1.NewIdentityInternalServiceClient(conn)
				_, healthErr = client.HealthCheck(checkCtx, &common_v1.ServiceHealthRequest{})
			case "WikiReadService":
				client := wiki_v1.NewWikiReadServiceClient(conn)
				_, healthErr = client.HealthCheck(checkCtx, &common_v1.ServiceHealthRequest{})
			case "WikiWriteService":
				client := wiki_v1.NewWikiWriteServiceClient(conn)
				_, healthErr = client.HealthCheck(checkCtx, &common_v1.ServiceHealthRequest{})
			case "MediaService":
				client := media_v1.NewMediaServiceClient(conn)
				_, healthErr = client.HealthCheck(checkCtx, &common_v1.ServiceHealthRequest{})
			case "SearchService":
				client := search_v1.NewSearchServiceClient(conn)
				_, healthErr = client.HealthCheck(checkCtx, &common_v1.ServiceHealthRequest{})
			default:
				loggerEntry.Tracef("skipping health check for unknown service: %s", serviceCfg.Name)
			}

			checkCancel()

			if healthErr != nil {
				isTimeout := status.Code(healthErr) == codes.DeadlineExceeded ||
					errors.Is(healthErr, context.DeadlineExceeded)

				if isTimeout {
					loggerEntry.Errorf(
						"health check for gRPC service %s at %s timed out after 5s",
						serviceCfg.Name,
						serviceCfg.Address,
					)
				} else {
					loggerEntry.Errorf(
						"health check failed for gRPC service %s at %s: %v",
						serviceCfg.Name,
						serviceCfg.Address,
						healthErr,
					)
				}

				sci.dropConn(conn)

				select {
				case <-healthCtx.Done():
					return
				case <-ticker.C:
					continue
				}
			}

			loggerEntry.Debugf("service %s is healthy", serviceCfg.Name)

			if !registered {
				loggerEntry.Tracef("registering gRPC service handlers for %s...", serviceCfg.Name)

				for _, registerEntry := range serviceCfg.RegisterEntries {
					if err := registerEntry.HandlerRegisterFunc(healthCtx, mux, conn); err != nil {
						loggerEntry.Errorf(
							"failed to register gRPC service handler '%s' for %s: %v",
							registerEntry.HandlerName,
							serviceCfg.Name,
							err,
						)

						sci.dropConn(conn)

						select {
						case <-healthCtx.Done():
							return
						case <-ticker.C:
							continue
						}
					}

					loggerEntry.Tracef(
						"successfully registered gRPC service handler '%s' for %s...",
						registerEntry.HandlerName,
						serviceCfg.Name,
					)
				}

				sci.mu.Lock()

				if sci.Conn == conn {
					sci.Registered = true
				}

				sci.mu.Unlock()

				loggerEntry.Infof("service %s is healthy and registered", serviceCfg.Name)
			}

			select {
			case <-healthCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}(sci.Config, sci.Mux)
}
