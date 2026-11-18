package dialer

import (
	"fmt"
	"time"

	"github.com/delimitrou/DeathStarBench/tree/master/hotelReservation/tls"
	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
	consul "github.com/hashicorp/consul/api"
	opentracing "github.com/opentracing/opentracing-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/attributes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/resolver"
)

// DialOption allows optional config for dialer
type DialOption func(name string) (grpc.DialOption, error)

// WithTracer traces rpc calls
func WithTracer(tracer opentracing.Tracer) DialOption {
	return func(name string) (grpc.DialOption, error) {
		return grpc.WithUnaryInterceptor(otgrpc.OpenTracingClientInterceptor(tracer)), nil
	}
}

// WithBalancer enables client side load balancing
func WithBalancer(registry *consul.Client) DialOption {
	return func(name string) (grpc.DialOption, error) {
		return grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`), nil
	}
}

// Dial returns a load balanced grpc client conn with tracing interceptor
func Dial(name string, opts ...DialOption) (*grpc.ClientConn, error) {
	return dial(name, name, nil, opts)
}

// DialPool is Dial for a plain host:port, which it keeps a pool of conns
// connections to rather than one, and spreads the calls across round robin.
//
// A single HTTP/2 connection carries every call otherwise. gRPC recommends a
// pool of channels under high load, and a proxy that serves each connection on
// one thread, like Envoy, cannot spread a single one over more than one core.
func DialPool(addr string, conns int, opts ...DialOption) (*grpc.ClientConn, error) {
	if conns <= 1 {
		return Dial(addr, opts...)
	}

	extra := []grpc.DialOption{
		grpc.WithResolvers(&poolBuilder{addr: addr, conns: conns}),
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`),
	}
	return dial(addr, poolScheme+":///"+addr, extra, opts)
}

func dial(name, target string, extra []grpc.DialOption, opts []DialOption) (*grpc.ClientConn, error) {
	dialopts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Timeout:             120 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if tlsopt := tls.GetDialOpt(); tlsopt != nil {
		dialopts = append(dialopts, tlsopt)
	} else {
		dialopts = append(dialopts, grpc.WithInsecure())
	}

	for _, fn := range opts {
		opt, err := fn(name)
		if err != nil {
			return nil, fmt.Errorf("config error: %v", err)
		}
		dialopts = append(dialopts, opt)
	}
	dialopts = append(dialopts, extra...)

	conn, err := grpc.Dial(target, dialopts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %v", target, err)
	}

	return conn, nil
}

const poolScheme = "pool"

// poolIndex tells the addresses poolBuilder resolves to apart, round_robin
// only opens one connection per distinct address
type poolIndex struct{}

// poolBuilder resolves to its address conns times
type poolBuilder struct {
	addr  string
	conns int
}

func (b *poolBuilder) Build(_ resolver.Target, cc resolver.ClientConn, _ resolver.BuildOptions) (resolver.Resolver, error) {
	addrs := make([]resolver.Address, b.conns)
	for i := range addrs {
		addrs[i] = resolver.Address{
			Addr:       b.addr,
			Attributes: attributes.New(poolIndex{}, i),
		}
	}
	if err := cc.UpdateState(resolver.State{Addresses: addrs}); err != nil {
		return nil, err
	}
	return poolResolver{}, nil
}

func (b *poolBuilder) Scheme() string { return poolScheme }

// poolResolver has nothing to resolve after the first time
type poolResolver struct{}

func (poolResolver) ResolveNow(resolver.ResolveNowOptions) {}
func (poolResolver) Close()                                {}
