package consensus

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"Go-Blockchain-KYC/models"
)

// RaftState represents the state of a Raft node
type RaftState string

const (
	Follower  RaftState = "follower"
	Candidate RaftState = "candidate"
	Leader    RaftState = "leader"
)

// Raft implements Raft consensus mechanism
type Raft struct {
	nodeID            string
	nodes             []Node
	state             RaftState
	currentTerm       int64
	votedFor          string
	log               []*LogEntry
	commitIndex       int64
	lastApplied       int64
	nextIndex         map[string]int64
	matchIndex        map[string]int64
	electionTimeout   time.Duration
	heartbeatInterval time.Duration
	mutex             sync.RWMutex
	voteChan          chan *VoteRequest
	appendChan        chan *AppendRequest
	commitChan        chan *models.Block
	stopChan          chan struct{}
	electionTimer     *time.Timer
	isRunning         bool
}

// LogEntry represents a log entry in Raft
type LogEntry struct {
	Term    int64         `json:"term"`
	Index   int64         `json:"index"`
	Block   *models.Block `json:"block"`
	Command string        `json:"command"`
}

// VoteRequest represents a vote request
type VoteRequest struct {
	Term         int64  `json:"term"`
	CandidateID  string `json:"candidate_id"`
	LastLogIndex int64  `json:"last_log_index"`
	LastLogTerm  int64  `json:"last_log_term"`
}

// VoteResponse represents a vote response
type VoteResponse struct {
	Term        int64 `json:"term"`
	VoteGranted bool  `json:"vote_granted"`
}

// AppendRequest represents an append entries request
type AppendRequest struct {
	Term         int64       `json:"term"`
	LeaderID     string      `json:"leader_id"`
	PrevLogIndex int64       `json:"prev_log_index"`
	PrevLogTerm  int64       `json:"prev_log_term"`
	Entries      []*LogEntry `json:"entries"`
	LeaderCommit int64       `json:"leader_commit"`
}

// AppendResponse represents an append entries response
type AppendResponse struct {
	Term    int64 `json:"term"`
	Success bool  `json:"success"`
}

// NewRaft creates a new Raft consensus instance
func NewRaft(config ConsensusConfig) *Raft {
	raft := &Raft{
		nodeID:            config.NodeID,
		nodes:             config.Nodes,
		state:             Follower,
		currentTerm:       0,
		votedFor:          "",
		log:               []*LogEntry{},
		commitIndex:       0,
		lastApplied:       0,
		nextIndex:         make(map[string]int64),
		matchIndex:        make(map[string]int64),
		electionTimeout:   time.Duration(150+rand.Intn(150)) * time.Millisecond,
		heartbeatInterval: 50 * time.Millisecond,
		voteChan:          make(chan *VoteRequest, 100),
		appendChan:        make(chan *AppendRequest, 100),
		commitChan:        make(chan *models.Block, 100),
		stopChan:          make(chan struct{}),
	}

	return raft
}

// Start starts the Raft consensus mechanism
func (r *Raft) Start() error {
	r.mutex.Lock()
	if r.isRunning {
		r.mutex.Unlock()
		return errors.New("Raft already running")
	}
	r.isRunning = true
	r.mutex.Unlock()

	r.resetElectionTimer()
	go r.run()
	return nil
}

// Stop stops the Raft consensus mechanism
func (r *Raft) Stop() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.isRunning {
		return errors.New("Raft not running")
	}

	close(r.stopChan)
	r.isRunning = false
	return nil
}

// run is the main loop for Raft
func (r *Raft) run() {
	for {
		select {
		case <-r.stopChan:
			return
		case voteReq := <-r.voteChan:
			r.handleVoteRequest(voteReq)
		case appendReq := <-r.appendChan:
			r.handleAppendEntries(appendReq)
		case <-r.electionTimer.C:
			r.startElection()
		}
	}
}

// resetElectionTimer resets the election timeout timer
func (r *Raft) resetElectionTimer() {
	if r.electionTimer != nil {
		r.electionTimer.Stop()
	}
	timeout := time.Duration(150+rand.Intn(150)) * time.Millisecond
	r.electionTimer = time.NewTimer(timeout)
}

// startElection starts a new election
func (r *Raft) startElection() {
	r.mutex.Lock()
	r.state = Candidate
	r.currentTerm++
	r.votedFor = r.nodeID
	currentTerm := r.currentTerm
	r.mutex.Unlock()

	votes := 1 // Vote for self

	// Request votes from all other nodes
	for _, node := range r.nodes {
		if node.ID == r.nodeID {
			continue
		}

		// In production, send over network
		voteReq := &VoteRequest{
			Term:         currentTerm,
			CandidateID:  r.nodeID,
			LastLogIndex: r.getLastLogIndex(),
			LastLogTerm:  r.getLastLogTerm(),
		}

		// Simulate vote response
		response := r.requestVote(node.ID, voteReq)
		if response != nil && response.VoteGranted {
			votes++
		}
	}

	// Check if we won the election
	r.mutex.Lock()
	if votes > len(r.nodes)/2 && r.state == Candidate {
		r.becomeLeader()
	} else {
		r.state = Follower
		r.resetElectionTimer()
	}
	r.mutex.Unlock()
}

// becomeLeader transitions to leader state
func (r *Raft) becomeLeader() {
	r.state = Leader

	// Initialize nextIndex and matchIndex
	lastLogIndex := r.getLastLogIndex()
	for _, node := range r.nodes {
		r.nextIndex[node.ID] = lastLogIndex + 1
		r.matchIndex[node.ID] = 0
	}

	// Start sending heartbeats
	go r.sendHeartbeats()
}

// sendHeartbeats sends heartbeats to all followers
func (r *Raft) sendHeartbeats() {
	ticker := time.NewTicker(r.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopChan:
			return
		case <-ticker.C:
			r.mutex.RLock()
			if r.state != Leader {
				r.mutex.RUnlock()
				return
			}
			r.mutex.RUnlock()

			for _, node := range r.nodes {
				if node.ID == r.nodeID {
					continue
				}
				go r.sendAppendEntries(node.ID)
			}
		}
	}
}

// sendAppendEntries sends append entries to a follower
func (r *Raft) sendAppendEntries(nodeID string) {
	r.mutex.RLock()
	prevLogIndex := r.nextIndex[nodeID] - 1
	var prevLogTerm int64
	if prevLogIndex > 0 && prevLogIndex <= int64(len(r.log)) {
		prevLogTerm = r.log[prevLogIndex-1].Term
	}

	entries := []*LogEntry{}
	if r.nextIndex[nodeID] <= int64(len(r.log)) {
		entries = r.log[r.nextIndex[nodeID]-1:]
	}

	req := &AppendRequest{
		Term:         r.currentTerm,
		LeaderID:     r.nodeID,
		PrevLogIndex: prevLogIndex,
		PrevLogTerm:  prevLogTerm,
		Entries:      entries,
		LeaderCommit: r.commitIndex,
	}
	r.mutex.RUnlock()

	// In production, send over network
	_ = req
}

// handleVoteRequest handles incoming vote requests
func (r *Raft) handleVoteRequest(req *VoteRequest) *VoteResponse {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	response := &VoteResponse{
		Term:        r.currentTerm,
		VoteGranted: false,
	}

	if req.Term < r.currentTerm {
		return response
	}

	if req.Term > r.currentTerm {
		r.currentTerm = req.Term
		r.state = Follower
		r.votedFor = ""
	}

	if (r.votedFor == "" || r.votedFor == req.CandidateID) &&
		r.isLogUpToDate(req.LastLogIndex, req.LastLogTerm) {
		r.votedFor = req.CandidateID
		response.VoteGranted = true
		r.resetElectionTimer()
	}

	return response
}

// handleAppendEntries handles incoming append entries requests
func (r *Raft) handleAppendEntries(req *AppendRequest) *AppendResponse {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	response := &AppendResponse{
		Term:    r.currentTerm,
		Success: false,
	}

	if req.Term < r.currentTerm {
		return response
	}

	r.resetElectionTimer()

	if req.Term > r.currentTerm {
		r.currentTerm = req.Term
		r.state = Follower
		r.votedFor = ""
	}

	// Check log consistency
	if req.PrevLogIndex > 0 {
		if req.PrevLogIndex > int64(len(r.log)) {
			return response
		}
		if r.log[req.PrevLogIndex-1].Term != req.PrevLogTerm {
			return response
		}
	}

	// Append entries
	for i, entry := range req.Entries {
		index := req.PrevLogIndex + int64(i) + 1
		if index <= int64(len(r.log)) {
			if r.log[index-1].Term != entry.Term {
				r.log = r.log[:index-1]
				r.log = append(r.log, entry)
			}
		} else {
			r.log = append(r.log, entry)
		}
	}

	// Update commit index
	if req.LeaderCommit > r.commitIndex {
		if req.LeaderCommit < int64(len(r.log)) {
			r.commitIndex = req.LeaderCommit
		} else {
			r.commitIndex = int64(len(r.log))
		}
	}

	response.Success = true
	return response
}

// requestVote sends a vote request to a node
func (r *Raft) requestVote(nodeID string, req *VoteRequest) *VoteResponse {
	// In production, send over network
	// For simulation, return a vote
	return &VoteResponse{
		Term:        req.Term,
		VoteGranted: true,
	}
}

// isLogUpToDate checks if candidate's log is up to date
func (r *Raft) isLogUpToDate(lastLogIndex, lastLogTerm int64) bool {
	myLastIndex := r.getLastLogIndex()
	myLastTerm := r.getLastLogTerm()

	if lastLogTerm != myLastTerm {
		return lastLogTerm > myLastTerm
	}
	return lastLogIndex >= myLastIndex
}

// getLastLogIndex returns the last log index
func (r *Raft) getLastLogIndex() int64 {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return int64(len(r.log))
}

// getLastLogTerm returns the last log term
func (r *Raft) getLastLogTerm() int64 {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	if len(r.log) == 0 {
		return 0
	}
	return r.log[len(r.log)-1].Term
}

// ProposeBlock proposes a new block for consensus
func (r *Raft) ProposeBlock(block *models.Block) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.state != Leader {
		return errors.New("not the leader")
	}

	entry := &LogEntry{
		Term:    r.currentTerm,
		Index:   int64(len(r.log)) + 1,
		Block:   block,
		Command: "add_block",
	}

	r.log = append(r.log, entry)
	return nil
}

// ValidateBlock validates a proposed block
func (r *Raft) ValidateBlock(block *models.Block) bool {
	if block == nil {
		return false
	}
	return block.Validate()
}

// CommitBlock commits a block after consensus
func (r *Raft) CommitBlock(block *models.Block) error {
	r.commitChan <- block
	return nil
}

// GetState returns the current consensus state
func (r *Raft) GetState() ConsensusState {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	switch r.state {
	case Leader:
		return StateFinalized
	case Candidate:
		return StatePrepare
	default:
		return StateIdle
	}
}

// IsLeader returns whether this node is the leader
func (r *Raft) IsLeader() bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.state == Leader
}

// GetCommitChannel returns the channel for committed blocks
func (r *Raft) GetCommitChannel() <-chan *models.Block {
	return r.commitChan
}

// UpdateNodes updates the list of consensus nodes
func (r *Raft) UpdateNodes(nodes []Node) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	oldNodeCount := len(r.nodes)
	r.nodes = nodes

	// Reinitialize nextIndex and matchIndex for new nodes
	for _, node := range nodes {
		if _, exists := r.nextIndex[node.ID]; !exists {
			r.nextIndex[node.ID] = r.getLastLogIndexUnlocked() + 1
			r.matchIndex[node.ID] = 0
		}
	}

	// Remove entries for nodes that are no longer present
	currentNodeIDs := make(map[string]bool)
	for _, node := range nodes {
		currentNodeIDs[node.ID] = true
	}

	for nodeID := range r.nextIndex {
		if !currentNodeIDs[nodeID] {
			delete(r.nextIndex, nodeID)
			delete(r.matchIndex, nodeID)
		}
	}

	// Log node changes
	if len(nodes) != oldNodeCount {
		// Node count changed - may need to recalculate quorum
	}
}

// GetNodes returns all known nodes
func (r *Raft) GetNodes() []Node {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy
	nodes := make([]Node, len(r.nodes))
	copy(nodes, r.nodes)
	return nodes
}

// GetNodeID returns this node's ID
func (r *Raft) GetNodeID() string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.nodeID
}

// getLastLogIndexUnlocked returns last log index without locking (caller must hold lock)
func (r *Raft) getLastLogIndexUnlocked() int64 {
	return int64(len(r.log))
}
