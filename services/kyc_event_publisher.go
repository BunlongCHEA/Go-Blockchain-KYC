// services/kyc_event_publisher.go
package services

import (
	"Go-Blockchain-KYC/crypto"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	KeyVersion string `json:"key_version"` // for key rotation
	Ciphertext string `json:"ciphertext"`  // base64(nonce || GCM ciphertext)
	// Signature  string `json:"signature"`  // HMAC-SHA256 over message_id+timestamp+ciphertext
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
	keyMgr     *crypto.MQKeyManager
	exchange   string
	routingKey string
}

type KYCEventPublisherConfig struct {
	AMQPURL    string // amqps://user:pass@host:5671/vhost  (TLS URI)
	Exchange   string
	RoutingKey string
	// AESKey     []byte // 32-byte key for AES-256-GCM
	// HMACKey    []byte // 32-byte key for HMAC-SHA256
}

func NewKYCEventPublisher(cfg *KYCEventPublisherConfig, keyMgr *crypto.MQKeyManager) (*KYCEventPublisher, error) {
	if keyMgr == nil {
		return nil, fmt.Errorf("mq key manager is required")
	}
	p := &KYCEventPublisher{cfg: cfg, keyMgr: keyMgr, exchange: cfg.Exchange, routingKey: cfg.RoutingKey}
	if err := p.connect(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *KYCEventPublisher) connect() error {
	conn, err := amqp.Dial(p.cfg.AMQPURL) // amqps:// → TLS automatically
	if err != nil {
		return fmt.Errorf("RabbitMQ dial: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("RabbitMQ channel: %w", err)
	}
	if err := ch.ExchangeDeclare(p.exchange, "topic", true, false, false, false, nil); err != nil {
		return fmt.Errorf("exchange declare: %w", err)
	}
	p.conn, p.ch = conn, ch
	return nil
}

// PublishStatusChange is called by SuspendKYC and ExpireKYC handlers.
func (p *KYCEventPublisher) PublishStatusChange(
	ctx context.Context, customerID, kycStatus, bankID, actor string,
) error {
	payload := kycStatusPayload{
		CustomerID: customerID, KYCStatus: kycStatus, BankID: bankID,
		Actor: actor, ChangedAt: time.Now().Unix(),
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	keyVersion, key, err := p.keyMgr.GetActive()
	if err != nil {
		return fmt.Errorf("get active mq key: %w", err)
	}

	msgID := generateMessageID()
	ts := time.Now().Unix()
	eventType := "KYC_STATUS_CHANGED"

	// AAD binds the envelope metadata into the GCM auth tag — tampering with
	// ANY of these fields after encryption causes Open() to fail on the consumer.
	aad := []byte(fmt.Sprintf("%s|%d|%s|%s", msgID, ts, eventType, keyVersion))

	ciphertext, err := encryptGCM(key, plaintext, aad)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	env := KYCEventEnvelope{
		MessageID: msgID, Timestamp: ts, EventType: eventType,
		KeyVersion: keyVersion, Ciphertext: ciphertext,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	pub := amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		MessageId:    msgID,
		Timestamp:    time.Unix(ts, 0),
		Body:         body,
	}

	if err := p.ch.PublishWithContext(ctx, p.exchange, p.routingKey, false, false, pub); err != nil {
		log.Printf("[KYCEventPublisher] publish failed, reconnecting: %v", err)
		if reErr := p.connect(); reErr != nil {
			return fmt.Errorf("reconnect failed: %w", reErr)
		}
		return p.ch.PublishWithContext(ctx, p.exchange, p.routingKey, false, false, pub)
	}

	log.Printf("[KYCEventPublisher] published %s customer=%s status=%s key=%s",
		msgID, customerID, kycStatus, keyVersion)
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

// ─── AES-256-GCM helpers ─────────────────────────────────────────────────────

func encryptGCM(key, plaintext, aad []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, aad) // nonce prepended, AAD authenticated not encrypted
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func generateMessageID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
