package bridge

// RunDNAAnalyze calls the Rust engine to classify a slice of plaintext passwords.
func RunDNAAnalyze(plaintexts []string) (*Message, error) {
	req := JobRequest{
		Type:       "dna_analyze",
		Plaintexts: plaintexts,
	}
	return call(req, nil)
}

// RunPolicyCheck checks one plaintext for policy bypasses via the Rust engine.
func RunPolicyCheck(plaintext string) (*Message, error) {
	req := JobRequest{
		Type:      "policy_check",
		Plaintext: plaintext,
	}
	return call(req, nil)
}

// RunPredict predicts crack difficulty for an algorithm via the Rust engine.
func RunPredict(algorithm string) (*Message, error) {
	req := JobRequest{
		Type:      "predict",
		Algorithm: algorithm,
	}
	return call(req, nil)
}
