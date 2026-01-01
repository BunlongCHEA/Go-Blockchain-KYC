package consensus

import (
	"errors"
	"sync"
	"time"

	"Go-Blockchain-KYC/models"
)

// PBFT implements Practical Byzantine Fault Tolerance consensus
type PBFT struct {
	nodeID     string
	nodes      []Node
	state      ConsensusState
	viewNum    int64
	seqNum     int64
	leader     string
	prepareLog map[string]map[string]bool // seqNum -> nodeID -> prepared
	commitLog  map[string]map[string]bool // seqNum -> nodeID -> committed
	messageLog []*Message
	mutex      sync.RWMutex
	msgChan    chan *Message
	commitChan chan *models.Block
	stopChan   chan struct{}
	timeout    time.Duration
	isRunning  bool
}

// NewPBFT creates a new PBFT consensus instance
func NewPBFT(config ConsensusConfig) *PBFT {
	pbft := &PBFT{
		nodeID:     config.NodeID,
		nodes:      config.Nodes,
		state:      StateIdle,
		viewNum:    0,
		seqNum:     0,
		prepareLog: make(map[string]map[string]bool),
		commitLog:  make(map[string]map[string]bool),
		messageLog: []*Message{},
		msgChan:    make(chan *Message, 1000),
		commitChan: make(chan *models.Block, 100),
		stopChan:   make(chan struct{}),
		timeout:    time.Duration(config.Timeout) * time.Millisecond,
	}

	// Set initial leader (first node)
	if len(config.Nodes) > 0 {
		pbft.leader = config.Nodes[0].ID
	}

	return pbft
}

// Start starts the PBFT consensus mechanism
func (p *PBFT) Start() error {
	p.mutex.Lock()
	if p.isRunning {
		p.mutex.Unlock()
		return errors.New("PBFT already running")
	}
	p.isRunning = true
	p.mutex.Unlock()

	go p.messageLoop()
	return nil
}

// Stop stops the PBFT consensus mechanism
func (p *PBFT) Stop() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.isRunning {
		return errors.New("PBFT not running")
	}

	close(p.stopChan)
	p.isRunning = false
	return nil
}

// messageLoop processes consensus messages
func (p *PBFT) messageLoop() {
	for {
		select {
		case msg := <-p.msgChan:
			p.handleMessage(msg)
		case <-p.stopChan:
			return
		}
	}
}

// handleMessage handles incoming consensus messages
func (p *PBFT) handleMessage(msg *Message) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	switch msg.Type {
	case MsgPrePrepare:
		p.handlePrePrepare(msg)
	case MsgPrepare:
		p.handlePrepare(msg)
	case MsgCommit:
		p.handleCommit(msg)
	case MsgViewChange:
		p.handleViewChange(msg)
	}
}

// ProposeBlock proposes a new block for consensus
func (p *PBFT) ProposeBlock(block *models.Block) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.IsLeader() {
		return errors.New("only leader can propose blocks")
	}

	p.seqNum++
	p.state = StatePrePrepare

	// Create pre-prepare message
	msg := &Message{
		Type:    MsgPrePrepare,
		NodeID:  p.nodeID,
		Block:   block,
		ViewNum: p.viewNum,
		SeqNum:  p.seqNum,
	}

	// Broadcast pre-prepare to all nodes
	p.broadcast(msg)

	return nil
}

// handlePrePrepare handles pre-prepare messages
func (p *PBFT) handlePrePrepare(msg *Message) {
	// Verify the message is from the leader
	if msg.NodeID != p.leader {
		return
	}

	// Verify view number matches
	if msg.ViewNum != p.viewNum {
		return
	}

	// Validate the block
	if !p.ValidateBlock(msg.Block) {
		return
	}

	p.state = StatePrepare
	p.messageLog = append(p.messageLog, msg)

	// Send prepare message
	prepareMsg := &Message{
		Type:    MsgPrepare,
		NodeID:  p.nodeID,
		Block:   msg.Block,
		ViewNum: msg.ViewNum,
		SeqNum:  msg.SeqNum,
	}

	p.broadcast(prepareMsg)
}

// handlePrepare handles prepare messages
func (p *PBFT) handlePrepare(msg *Message) {
	seqKey := string(rune(msg.SeqNum))

	if p.prepareLog[seqKey] == nil {
		p.prepareLog[seqKey] = make(map[string]bool)
	}
	p.prepareLog[seqKey][msg.NodeID] = true

	// Check if we have 2f+1 prepare messages (where n = 3f+1)
	requiredPrepares := p.getRequiredVotes()
	if len(p.prepareLog[seqKey]) >= requiredPrepares {
		p.state = StateCommit

		// Send commit message
		commitMsg := &Message{
			Type:    MsgCommit,
			NodeID:  p.nodeID,
			Block:   msg.Block,
			ViewNum: msg.ViewNum,
			SeqNum:  msg.SeqNum,
		}

		p.broadcast(commitMsg)
	}
}

// handleCommit handles commit messages
func (p *PBFT) handleCommit(msg *Message) {
	seqKey := string(rune(msg.SeqNum))

	if p.commitLog[seqKey] == nil {
		p.commitLog[seqKey] = make(map[string]bool)
	}
	p.commitLog[seqKey][msg.NodeID] = true

	// Check if we have 2f+1 commit messages
	requiredCommits := p.getRequiredVotes()
	if len(p.commitLog[seqKey]) >= requiredCommits {
		p.state = StateFinalized

		// Commit the block
		if msg.Block != nil {
			p.commitChan <- msg.Block
		}
	}
}

// handleViewChange handles view change messages
func (p *PBFT) handleViewChange(msg *Message) {
	// Increment view number and elect new leader
	p.viewNum++
	leaderIndex := int(p.viewNum) % len(p.nodes)
	p.leader = p.nodes[leaderIndex].ID
	p.state = StateIdle
}

// ValidateBlock validates a proposed block
func (p *PBFT) ValidateBlock(block *models.Block) bool {
	if block == nil {
		return false
	}
	return block.Validate()
}

// CommitBlock commits a block after consensus
func (p *PBFT) CommitBlock(block *models.Block) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.state = StateFinalized
	return nil
}

// GetState returns the current consensus state
func (p *PBFT) GetState() ConsensusState {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.state
}

// IsLeader returns whether this node is the leader
func (p *PBFT) IsLeader() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.nodeID == p.leader
}

// broadcast sends a message to all nodes
func (p *PBFT) broadcast(msg *Message) {
	// In production, this would send over network
	// For now, we just add to the message channel
	p.msgChan <- msg
}

// getRequiredVotes returns the number of votes required (2f+1)
func (p *PBFT) getRequiredVotes() int {
	n := len(p.nodes)
	f := (n - 1) / 3
	return 2*f + 1
}

// GetCommitChannel returns the channel for committed blocks
func (p *PBFT) GetCommitChannel() <-chan *models.Block {
	return p.commitChan
}
