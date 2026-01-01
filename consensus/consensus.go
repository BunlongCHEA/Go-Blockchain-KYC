package consensus

import (
	"Go-Blockchain-KYC/models"
)

// ConsensusType represents the type of consensus mechanism
type ConsensusType string

const (
	ConsensusPBFT ConsensusType = "pbft"
	ConsensusRaft ConsensusType = "raft"
)

// Consensus defines the interface for consensus mechanisms
type Consensus interface {
	// ProposeBlock proposes a new block for consensus
	ProposeBlock(block *models.Block) error

	// ValidateBlock validates a proposed block
	ValidateBlock(block *models.Block) bool

	// CommitBlock commits a block after consensus
	CommitBlock(block *models.Block) error

	// GetState returns the current consensus state
	GetState() ConsensusState

	// IsLeader returns whether this node is the leader
	IsLeader() bool

	// Start starts the consensus mechanism
	Start() error

	// Stop stops the consensus mechanism
	Stop() error
}

// ConsensusState represents the current state of consensus
type ConsensusState string

const (
	StateIdle       ConsensusState = "idle"
	StatePrePrepare ConsensusState = "pre_prepare"
	StatePrepare    ConsensusState = "prepare"
	StateCommit     ConsensusState = "commit"
	StateFinalized  ConsensusState = "finalized"
)

// Node represents a node in the consensus network
type Node struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	IsActive  bool   `json:"is_active"`
}

// Message represents a consensus message
type Message struct {
	Type      MessageType   `json:"type"`
	NodeID    string        `json:"node_id"`
	Block     *models.Block `json:"block,omitempty"`
	Signature string        `json:"signature"`
	ViewNum   int64         `json:"view_num"`
	SeqNum    int64         `json:"seq_num"`
}

// MessageType represents the type of consensus message
type MessageType string

const (
	MsgPrePrepare MessageType = "pre_prepare"
	MsgPrepare    MessageType = "prepare"
	MsgCommit     MessageType = "commit"
	MsgViewChange MessageType = "view_change"
	MsgNewView    MessageType = "new_view"
)

// ConsensusConfig holds consensus configuration
type ConsensusConfig struct {
	Type    ConsensusType
	NodeID  string
	Nodes   []Node
	Timeout int64
}

// NewConsensus creates a new consensus mechanism based on type
func NewConsensus(config ConsensusConfig) Consensus {
	switch config.Type {
	case ConsensusPBFT:
		return NewPBFT(config)
	case ConsensusRaft:
		return NewRaft(config)
	default:
		return NewPBFT(config)
	}
}
