// services/kyc_event_publisher.go
package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ─── Wire envelope ─────────────────────────────────────────────────────────
// Only the outer envelope fields are visible in the broker.
// The inner payload is AES-256-GCM encrypted so the broker operator
// cannot read customer PII even with direct queue access.
//
// Wire format:
//   {
//     "message_id":  "<UUIDv4>",          // idempotency key for CBS consumer
//     "timestamp":   1748000000,           // Unix epoch — CBS rejects if >5 min old
//     "event_type":  "KYC_STATUS_CHANGED",
//     "ciphertext":  "<base64(nonce||GCM(payload, aesKey))>",
//     "signature":   "<base64(HMAC-SHA256(message_id||timestamp||ciphertext, hmacKey))>"
//   }
//
// Inner payload (decrypted by CBS):
//   { "customer_id": "...", "kyc_status": "SUSPENDED"|"EXPIRED", "bank_id": "...", "actor": "..." }

type KYCEventEnvelope struct {
	MessageID  string `json:"message_id"`
	Timestamp  int64  `json:"timestamp"`
	EventType  string `json:"event_type"`
	Ciphertext string `json:"ciphertext"` // base64(nonce || GCM ciphertext)
	Signature  string `json:"signature"`  // HMAC-SHA256 over message_id+timestamp+ciphertext
}

type kycStatusPayload struct {
	CustomerID string `json:"customer_id"`
	KYCStatus  string `json:"kyc_status"` // "SUSPENDED" | "EXPIRED"
	BankID     string `json:"bank_id"`
	Actor      string `json:"actor"` // user_id or "system"
	ChangedAt  int64  `json:"changed_at"`
}

// ─── Publisher ─────────────────────────────────────────────────────────────

type KYCEventPublisher struct {
	conn       *amqp.Connection
	ch         *amqp.Channel
	mu         sync.Mutex
	cfg        *KYCEventPublisherConfig
	aesKey     []byte // 32 bytes, from env KYC_MQ_AES_KEY (base64)
	hmacKey    []byte // 32 bytes, from env KYC_MQ_HMAC_KEY (base64)
	exchange   string
	routingKey string
}

type KYCEventPublisherConfig struct {
	AMQPURL    string // amqps://user:pass@host:5671/vhost  (TLS URI)
	Exchange   string
	RoutingKey string
	AESKey     []byte // 32-byte key for AES-256-GCM
	HMACKey    []byte // 32-byte key for HMAC-SHA256
}

func NewKYCEventPublisher(cfg *KYCEventPublisherConfig) (*KYCEventPublisher, error) {
	if len(cfg.AESKey) != 32 {
		return nil, fmt.Errorf("KYC_MQ_AES_KEY must be exactly 32 bytes")
	}
	if len(cfg.HMACKey) != 32 {
		return nil, fmt.Errorf("KYC_MQ_HMAC_KEY must be exactly 32 bytes")
	}

	p := &KYCEventPublisher{
		cfg:        cfg,
		aesKey:     cfg.AESKey,
		hmacKey:    cfg.HMACKey,
		exchange:   cfg.Exchange,
		routingKey: cfg.RoutingKey,
	}
	if err := p.connect(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *KYCEventPublisher) connect() error {
	// amqp.DialTLS is used when AMQPURL starts with amqps://
	conn, err := amqp.Dial(p.cfg.AMQPURL)
	if err != nil {
		return fmt.Errorf("RabbitMQ dial: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("RabbitMQ channel: %w", err)
	}
	// Declare a durable topic exchange — CBS binds its queue to it.
	if err := ch.ExchangeDeclare(
		p.exchange, "topic", true, false, false, false, nil,
	); err != nil {
		return fmt.Errorf("exchange declare: %w", err)
	}
	p.conn = conn
	p.ch = ch
	return nil
}

// PublishStatusChange is called by SuspendKYC and ExpireKYC handlers.
func (p *KYCEventPublisher) PublishStatusChange(
	ctx context.Context,
	customerID, kycStatus, bankID, actor string,
) error {
	payload := kycStatusPayload{
		CustomerID: customerID,
		KYCStatus:  kycStatus,
		BankID:     bankID,
		Actor:      actor,
		ChangedAt:  time.Now().Unix(),
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	// ── Encrypt with AES-256-GCM ──────────────────────────────────────────
	block, err := aes.NewCipher(p.aesKey)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil) // nonce prepended
	ciphertext := base64.StdEncoding.EncodeToString(sealed)

	// ── Build outer envelope ──────────────────────────────────────────────
	msgID := generateMessageID()
	ts := time.Now().Unix()

	// ── HMAC over canonical string: message_id|timestamp|ciphertext ───────
	mac := hmac.New(sha256.New, p.hmacKey)
	fmt.Fprintf(mac, "%s|%d|%s", msgID, ts, ciphertext)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	env := KYCEventEnvelope{
		MessageID:  msgID,
		Timestamp:  ts,
		EventType:  "KYC_STATUS_CHANGED",
		Ciphertext: ciphertext,
		Signature:  sig,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	// ── Publish with reconnect on channel failure ─────────────────────────
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ch.PublishWithContext(ctx, p.exchange, p.routingKey, false, false,
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent, // survives broker restart
			MessageId:    msgID,
			Timestamp:    time.Unix(ts, 0),
			Body:         body,
		},
	); err != nil {
		// Reconnect once
		log.Printf("[KYCEventPublisher] publish failed, reconnecting: %v", err)
		if reconnErr := p.connect(); reconnErr != nil {
			return fmt.Errorf("reconnect failed: %w", reconnErr)
		}
		return p.ch.PublishWithContext(ctx, p.exchange, p.routingKey, false, false,
			amqp.Publishing{
				ContentType:  "application/json",
				DeliveryMode: amqp.Persistent,
				MessageId:    msgID,
				Timestamp:    time.Unix(ts, 0),
				Body:         body,
			},
		)
	}

	log.Printf("[KYCEventPublisher] published %s customer=%s status=%s", msgID, customerID, kycStatus)
	return nil
}

func (p *KYCEventPublisher) Close() {
	if p.ch != nil {
		p.ch.Close()
	}
	if p.conn != nil {
		p.conn.Close()
	}
}

func generateMessageID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
