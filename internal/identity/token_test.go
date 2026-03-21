// @gate-project: Gate
// @gate-path: internal/identity/token_test.go
package identity

import (
	"testing"
	"time"

	canon "github.com/Harshmaury/Canon/identity"
)

func testKeypair(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := generate(t.TempDir() + "/gate.key")
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return kp
}

func TestIssueAndVerify(t *testing.T) {
	kp := testKeypair(t)
	issuer := NewIssuer(kp)
	verifier := NewVerifier(kp)

	tests := []struct {
		name    string
		subject string
		scopes  []string
		ttl     time.Duration
		wantErr bool
	}{
		{
			name:    "developer token",
			subject: "harsh@github",
			scopes:  []string{canon.ScopeExecute, canon.ScopeObserve, canon.ScopeRegister},
			ttl:     24 * time.Hour,
		},
		{
			name:    "agent token",
			subject: "agent:local",
			scopes:  []string{canon.ScopeExecute},
			ttl:     time.Hour,
		},
		{
			name:    "ci token",
			subject: "ci:github-actions",
			scopes:  []string{canon.ScopeExecute, canon.ScopeObserve},
			ttl:     15 * time.Minute,
		},
		{
			name:    "observe-only token",
			subject: "dashboard@github",
			scopes:  []string{canon.ScopeObserve},
			ttl:     time.Hour,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signed, dto, err := issuer.Issue(tc.subject, tc.scopes, tc.ttl)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Issue() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if signed == "" {
				t.Fatal("Issue() returned empty token string")
			}
			if dto.Subject != tc.subject {
				t.Errorf("dto.Subject = %q, want %q", dto.Subject, tc.subject)
			}
			if dto.TokenID == "" {
				t.Error("dto.TokenID must not be empty")
			}

			claim, err := verifier.Verify(signed)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if claim.Subject != tc.subject {
				t.Errorf("claim.Subject = %q, want %q", claim.Subject, tc.subject)
			}
			if len(claim.Scopes) != len(tc.scopes) {
				t.Errorf("claim.Scopes = %v, want %v", claim.Scopes, tc.scopes)
			}
			if claim.TokenID == "" {
				t.Error("claim.TokenID must not be empty")
			}
		})
	}
}

func TestVerify_Expired(t *testing.T) {
	kp := testKeypair(t)
	iss := NewIssuer(kp)
	ver := NewVerifier(kp)

	signed, _, err := iss.Issue("test@github", []string{canon.ScopeObserve}, -time.Second)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	_, err = ver.Verify(signed)
	if err == nil {
		t.Fatal("Verify() expected error for expired token, got nil")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	kp1 := testKeypair(t)
	kp2 := testKeypair(t)
	iss := NewIssuer(kp1)
	ver := NewVerifier(kp2)

	signed, _, err := iss.Issue("test@github", []string{canon.ScopeExecute}, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	_, err = ver.Verify(signed)
	if err == nil {
		t.Fatal("Verify() expected error for wrong key, got nil")
	}
}

func TestVerify_Tampered(t *testing.T) {
	kp := testKeypair(t)
	iss := NewIssuer(kp)
	ver := NewVerifier(kp)

	signed, _, err := iss.Issue("test@github", []string{canon.ScopeExecute}, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	tampered := signed[:len(signed)-4] + "XXXX"
	_, err = ver.Verify(tampered)
	if err == nil {
		t.Fatal("Verify() expected error for tampered token, got nil")
	}
}

func TestHasScope(t *testing.T) {
	kp := testKeypair(t)
	iss := NewIssuer(kp)
	ver := NewVerifier(kp)

	signed, _, err := iss.Issue("test@github",
		[]string{canon.ScopeExecute, canon.ScopeObserve}, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	claim, err := ver.Verify(signed)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !claim.HasScope(canon.ScopeExecute) {
		t.Error("HasScope(execute) = false, want true")
	}
	if !claim.HasScope(canon.ScopeObserve) {
		t.Error("HasScope(observe) = false, want true")
	}
	if claim.HasScope(canon.ScopeAdmin) {
		t.Error("HasScope(admin) = true, want false")
	}
	if claim.HasScope(canon.ScopeRegister) {
		t.Error("HasScope(register) = true, want false")
	}
}
