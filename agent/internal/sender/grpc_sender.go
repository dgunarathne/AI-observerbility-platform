package sender

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// GRPCSender sends data to the AI engine via gRPC (using JSON payload for simplicity;
// swap to generated protobuf client once proto is compiled).
type GRPCSender struct {
	conn   *grpc.ClientConn
	logger *zap.Logger
	addr   string
}

func NewGRPCSender(addr string, logger *zap.Logger) (*GRPCSender, error) {
	conn, err := grpc.Dial(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             3 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithBlock(),
		grpc.WithTimeout(10*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	logger.Info("Connected to AI engine", zap.String("addr", addr))
	return &GRPCSender{conn: conn, logger: logger, addr: addr}, nil
}

// SendLogs ships a batch of log entries.
// Uses a raw bytes invoke until the proto client is generated.
func (s *GRPCSender) SendLogs(ctx context.Context, entries []LogEntry) error {
	payload, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal logs: %w", err)
	}

	// Invoke the IngestLogs RPC method on the ai.ObservabilityService service.
	var reply []byte
	err = s.conn.Invoke(ctx, "/ai.ObservabilityService/IngestLogs",
		&rawMessage{Data: payload}, &rawMessage{Data: reply})
	if err != nil {
		return fmt.Errorf("IngestLogs rpc: %w", err)
	}
	s.logger.Debug("Sent log batch", zap.Int("count", len(entries)))
	return nil
}

func (s *GRPCSender) SendMetrics(ctx context.Context, entries []MetricEntry) error {
	payload, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal metrics: %w", err)
	}

	var reply []byte
	err = s.conn.Invoke(ctx, "/ai.ObservabilityService/IngestMetrics",
		&rawMessage{Data: payload}, &rawMessage{Data: reply})
	if err != nil {
		return fmt.Errorf("IngestMetrics rpc: %w", err)
	}
	s.logger.Debug("Sent metric batch", zap.Int("count", len(entries)))
	return nil
}

func (s *GRPCSender) SendEvent(ctx context.Context, entry EventEntry) error {
	payload, err := json.Marshal([]EventEntry{entry})
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	var reply []byte
	err = s.conn.Invoke(ctx, "/ai.ObservabilityService/IngestEvents",
		&rawMessage{Data: payload}, &rawMessage{Data: reply})
	if err != nil {
		return fmt.Errorf("IngestEvents rpc: %w", err)
	}
	return nil
}

func (s *GRPCSender) SendAppHealthReports(ctx context.Context, reports []AppHealthReport) error {
	payload, err := json.Marshal(reports)
	if err != nil {
		return fmt.Errorf("marshal app health: %w", err)
	}
	var reply []byte
	if err := s.conn.Invoke(ctx, "/ai.ObservabilityService/IngestAppHealth",
		&rawMessage{Data: payload}, &rawMessage{Data: reply}); err != nil {
		return fmt.Errorf("IngestAppHealth rpc: %w", err)
	}
	s.logger.Debug("Sent app health reports", zap.Int("count", len(reports)))
	return nil
}

func (s *GRPCSender) SendClusterHealth(ctx context.Context, report ClusterHealthReport) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal cluster health: %w", err)
	}
	var reply []byte
	if err := s.conn.Invoke(ctx, "/ai.ObservabilityService/IngestClusterHealth",
		&rawMessage{Data: payload}, &rawMessage{Data: reply}); err != nil {
		return fmt.Errorf("IngestClusterHealth rpc: %w", err)
	}
	s.logger.Debug("Sent cluster health report")
	return nil
}

func (s *GRPCSender) SendSecurityThreat(ctx context.Context, threat ThreatIndicator) error {
	payload, err := json.Marshal([]ThreatIndicator{threat})
	if err != nil {
		return fmt.Errorf("marshal threat: %w", err)
	}
	var reply []byte
	if err := s.conn.Invoke(ctx, "/ai.ObservabilityService/IngestSecurityThreats",
		&rawMessage{Data: payload}, &rawMessage{Data: reply}); err != nil {
		return fmt.Errorf("IngestSecurityThreats rpc: %w", err)
	}
	s.logger.Info("Security threat sent", zap.String("category", threat.Category), zap.String("severity", threat.Severity))
	return nil
}

func (s *GRPCSender) Close() error {
	return s.conn.Close()
}

// rawMessage is a minimal proto.Message that carries raw bytes,
// used until the generated proto client is available.
type rawMessage struct {
	Data []byte
}

func (m *rawMessage) ProtoMessage()             {}
func (m *rawMessage) Reset()                    { m.Data = nil }
func (m *rawMessage) String() string            { return string(m.Data) }
func (m *rawMessage) Marshal() ([]byte, error)  { return m.Data, nil }
func (m *rawMessage) Unmarshal(b []byte) error  { m.Data = b; return nil }
