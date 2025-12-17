package config

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/proto/pkg/user"
	"github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"google.golang.org/grpc"
)

type RegisterFunc func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error

type GRPCService struct {
	Name     string
	Address  string
	Register RegisterFunc
}

type ServerConfig struct {
	HTTP struct {
		Host              string        `env:"HTTP_HOST" envDefault:"0.0.0.0"`
		Port              string        `env:"-"`
		ReadTimeout       time.Duration `env:"HTTP_READ_TIMEOUT" envDefault:"10s"`
		WriteTimeout      time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"10s"`
		IdleTimeout       time.Duration `env:"HTTP_IDLE_TIMEOUT" envDefault:"60s"`
		ReadHeaderTimeout time.Duration `env:"HTTP_READ_HEADER_TIMEOUT" envDefault:"5s"`
	} `envPrefix:"HTTP_"`

	Health struct {
		Host string `env:"HEALTH_HOST" envDefault:"0.0.0.0"`
		Port string `env:"-"`
	} `envPrefix:"HEALTH_"`

	GRPCServices []GRPCService `env:"-"`

	AppEnv string `env:"APP_ENV" envDefault:"dev"`
}

type ConfigProvider interface {
	GetHTTPConfig() HTTPServerConfig
	GetHealthConfig() HealthServerConfig
	GetGRPCServices() []GRPCService
}

type HTTPServerConfig struct {
	Host              string
	Port              string
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ReadHeaderTimeout time.Duration
}

type HealthServerConfig struct {
	Host string
	Port string
}

type serverConfigProvider struct {
	cfg *ServerConfig
}

func (p *serverConfigProvider) GetHTTPConfig() HTTPServerConfig {
	return HTTPServerConfig{
		Host:              p.cfg.HTTP.Host,
		Port:              p.cfg.HTTP.Port,
		ReadTimeout:       p.cfg.HTTP.ReadTimeout,
		WriteTimeout:      p.cfg.HTTP.WriteTimeout,
		IdleTimeout:       p.cfg.HTTP.IdleTimeout,
		ReadHeaderTimeout: p.cfg.HTTP.ReadHeaderTimeout,
	}
}

func (p *serverConfigProvider) GetHealthConfig() HealthServerConfig {
	return HealthServerConfig{
		Host: p.cfg.Health.Host,
		Port: p.cfg.Health.Port,
	}
}

func (p *serverConfigProvider) GetGRPCServices() []GRPCService {
	return p.cfg.GRPCServices
}

var (
	singletonConfigProvider ConfigProvider = nil
	onceProvider            sync.Once

	grpcServiceRegistry = map[string]struct {
		AddressEnv string
		Register   RegisterFunc
	}{
		"user": {
			AddressEnv: "USER_SERVICE_ENDPOINT",
			Register:   user.RegisterUserServiceHandler,
		},
	}
)

func LoadConfig() (*ServerConfig, error) {
	var (
		cfg            ServerConfig
		loadedServices []GRPCService
	)

	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse server config: %w", err)
	}

	for servicePrefix, registrationInfo := range grpcServiceRegistry {
		address := os.Getenv(registrationInfo.AddressEnv)

		if address == "" {
			logrus.Info(fmt.Sprintf("gRPC service address not configured for '%s' (env var: %s), skipping...", servicePrefix, registrationInfo.AddressEnv))
			continue
		}

		if registrationInfo.Register == nil {
			return nil, fmt.Errorf("internal config error: register function is nil for service '%s'", servicePrefix)
		}

		logrus.Infof("found gRPC service '%s' at address: %s", servicePrefix, address)

		loadedServices = append(loadedServices, GRPCService{
			Name:     cases.Title(language.English).String(servicePrefix) + "Service",
			Address:  address,
			Register: registrationInfo.Register,
		})
	}

	if len(loadedServices) == 0 {
		return nil, fmt.Errorf("no gRPC services were configured or found")
	}

	cfg.GRPCServices = loadedServices
	cfg.HTTP.Port = "8082"
	cfg.Health.Port = "8083"

	logrus.Info("configuration loaded successfully")

	logrus.Debugf("AppEnv: %s", cfg.AppEnv)
	logrus.Debugf("HTTP Host: %s, Port: %s", cfg.HTTP.Host, cfg.HTTP.Port)
	logrus.Debugf("Health Host: %s, Port: %s", cfg.Health.Host, cfg.Health.Port)

	for _, svc := range cfg.GRPCServices {
		logrus.Debugf("gRPC service: Name=%s, Address=%s", svc.Name, svc.Address)
	}

	return &cfg, nil
}
