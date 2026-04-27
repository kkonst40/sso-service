package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kkonst40/isso/internal/config"
	"github.com/segmentio/kafka-go"
)

type Producer struct {
	writer *kafka.Writer
}

func NewProducer(cfg *config.Config) *Producer {
	return &Producer{
		writer: &kafka.Writer{
			Addr:     kafka.TCP(fmt.Sprintf("%s:%s", cfg.Kafka.Host, cfg.Kafka.Port)),
			Topic:    topicUserEvents,
			Balancer: &kafka.Hash{},
		},
	}
}

func (p *Producer) SendLoginUpdate(ctx context.Context, userID uuid.UUID, login string) error {
	payloadBytes, _ := json.Marshal(loginUpdatePayload{UserID: userID, Login: login})

	event := eventMessage{
		Type:      eventTypeLoginUpdate,
		Payload:   payloadBytes,
		CreatedAt: time.Now(),
	}

	key := fmt.Appendf(nil, "user_%v", userID)
	val, _ := json.Marshal(event)

	return p.writer.WriteMessages(ctx, kafka.Message{
		Key:   key,
		Value: val,
	})
}

func (p *Producer) SendSessionInvalidation(ctx context.Context, sessionID uuid.UUID, ttlDays int) error {
	payloadBytes, _ := json.Marshal(sessionInvalidationPayload{SessionID: sessionID, TTLDays: ttlDays})

	event := eventMessage{
		Type:      eventTypeSessionInvalidation,
		Payload:   payloadBytes,
		CreatedAt: time.Now(),
	}

	val, _ := json.Marshal(event)
	key := fmt.Appendf(nil, "session_%v", sessionID)

	return p.writer.WriteMessages(ctx, kafka.Message{
		Key:   key,
		Value: val,
	})
}

func (p *Producer) Close() error {
	return p.writer.Close()
}
