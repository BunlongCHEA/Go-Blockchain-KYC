package models

// RecoveryData holds all data needed to restore blockchain state
type RecoveryData struct {
	Blocks       []*Block
	Transactions []*Transaction
	KYCRecords   []*KYCData
	Banks        []*Bank
}
