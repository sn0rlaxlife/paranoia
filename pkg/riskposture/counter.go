package riskposture

import (
	"fmt"
)

type Function struct {
	Name      string
	RiskLevel int
}

// RiskPosture is a struct that represents a risk posture.
type RiskPosture struct {
	// Functions is the list of functions.
	Functions []Function
}

// NewRiskPosture creates a new RiskPosture with the given functions.
func NewRiskPosture(functions []Function) RiskPosture {
	return RiskPosture{
		Functions: functions,
	}
}

// Define the risk thresholds
const lowRiskThreshold = 5
const mediumRiskThreshold = 10

var highRiskThreshold = 15

// CountRiskLevels counts the number of functions that meet each risk level.
func (rp *RiskPosture) CountRiskLevels() (int, int, int) {
	var lowRiskCount, mediumRiskCount, highRiskCount int
	for _, function := range rp.Functions {
		if function.RiskLevel <= lowRiskThreshold {
			lowRiskCount++
		} else if function.RiskLevel <= mediumRiskThreshold {
			mediumRiskCount++
		} else {
			highRiskCount++
		}
	}
	return lowRiskCount, mediumRiskCount, highRiskCount
}

// DisplayRiskLevels displays the risk levels.
func (rp *RiskPosture) DisplayRiskLevels() {
	lowRiskCount, mediumRiskCount, highRiskCount := rp.CountRiskLevels()
	fmt.Printf("Low risk: %d, Medium risk: %d, High risk: %d\n", lowRiskCount, mediumRiskCount, highRiskCount)
}
