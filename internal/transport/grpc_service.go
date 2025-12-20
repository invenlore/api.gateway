package transport

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/proto/pkg/user"
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
	mu            sync.RWMutex
}

func (sci *ServiceConnectionInfo) StartHealthCheck(ctx context.Context, dialOpts []grpc.DialOption) {
	healthCtx, cancel := context.WithCancel(ctx)
	sci.Cancel = cancel

	go func(serviceCfg *config.GRPCService, mux *runtime.ServeMux) {
		for {
			select {
			case <-healthCtx.Done():
				logrus.Debugf("health check for service %s stopped due to context cancellation", serviceCfg.Name)

				return
			default:
			}

			logrus.Debugf("performing health check for service %s...", serviceCfg.Name)
			sci.mu.Lock()

			if sci.Conn == nil {
				logrus.Debugf("attempting to dial gRPC service %s at %s...", serviceCfg.Name, serviceCfg.Address)

				conn, err := grpc.NewClient(serviceCfg.Address, dialOpts...)
				if err != nil {
					logrus.Errorf("failed to dial gRPC service %s at %s: %v, retrying in %s", serviceCfg.Name, serviceCfg.Address, err, sci.HealthTimeout)

					sci.Conn = nil
					sci.Registered = false

					sci.mu.Unlock()
					time.Sleep(sci.HealthTimeout)

					continue
				}

				logrus.Debugf("successfully dialed gRPC service %s at %s", serviceCfg.Name, serviceCfg.Address)
				sci.Conn = conn
			}

			checkCtx, checkCancel := context.WithTimeout(healthCtx, 5*time.Second)
			var healthErr error

			switch serviceCfg.Name {
			case "UserService":
				userClient := user.NewUserServiceClient(sci.Conn)
				_, healthErr = userClient.HealthCheck(checkCtx, &user.HealthRequest{})
			default:
				logrus.Warnf("skipping health check for unknown service: %s", serviceCfg.Name)
			}

			checkCancel()

			if healthErr != nil {
				isTimeout := status.Code(healthErr) == codes.DeadlineExceeded || errors.Is(healthErr, context.DeadlineExceeded)
				if isTimeout {
					logrus.Errorf("health check for gRPC service %s at %s timed out after 5s, retrying in %s", serviceCfg.Name, serviceCfg.Address, sci.HealthTimeout)
				} else {
					logrus.Errorf("health check failed for gRPC service %s at %s: %v, retrying in %s", serviceCfg.Name, serviceCfg.Address, healthErr, sci.HealthTimeout)
				}

				if sci.Conn != nil {
					sci.Conn.Close()
				}

				sci.Conn = nil
				sci.Registered = false

				sci.mu.Unlock()
				time.Sleep(sci.HealthTimeout)

				continue
			}

			logrus.Debugf("service %s is healthy", serviceCfg.Name)

			if !sci.Registered && sci.Conn != nil {
				logrus.Debugf("registering gRPC service handler for %s...", serviceCfg.Name)

				if err := serviceCfg.Register(healthCtx, mux, sci.Conn); err != nil {
					logrus.Errorf("failed to register gRPC service handler for %s: %v, retrying after %s", serviceCfg.Name, err, sci.HealthTimeout)

					if sci.Conn != nil {
						sci.Conn.Close()
					}

					sci.Conn = nil
					sci.Registered = false

					sci.mu.Unlock()
					time.Sleep(sci.HealthTimeout)

					continue
				}

				logrus.Debugf("successfully registered gRPC service: %s", serviceCfg.Name)
				logrus.Infof("service %s is healthy and registered", serviceCfg.Name)

				sci.Registered = true
			}

			sci.mu.Unlock()
			time.Sleep(sci.HealthTimeout)
		}
	}(sci.Config, sci.Mux)
}
