// @gate-project: Gate
// @gate-path: internal/provider/github.go
// GitHub OAuth provider for Gate identity (ADR-042).
// Handles the OAuth 2.0 code exchange and returns the GitHub login name as subject.
// Gate never stores GitHub tokens, emails, or profile data beyond the login name.
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	githubTokenURL = "https://github.com/login/oauth/access_token"
	githubUserURL  = "https://api.github.com/user"
)

// GitHubProvider exchanges a GitHub OAuth code for a platform subject string.
type GitHubProvider struct {
	clientID     string
	clientSecret string
	callbackURL  string
	httpClient   *http.Client
}

// NewGitHubProvider creates a GitHubProvider.
func NewGitHubProvider(clientID, clientSecret, callbackURL string) *GitHubProvider {
	return &GitHubProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURL:  callbackURL,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// AuthURL returns the GitHub OAuth authorization URL for the given state.
func (g *GitHubProvider) AuthURL(state string) string {
	params := url.Values{
		"client_id":    {g.clientID},
		"redirect_uri": {g.callbackURL},
		"scope":        {"read:user"},
		"state":        {state},
	}
	return "https://github.com/login/oauth/authorize?" + params.Encode()
}

// Exchange trades an OAuth code for the GitHub login name.
// Returns the login name as the platform subject: "<login>@github".
func (g *GitHubProvider) Exchange(ctx context.Context, code string) (string, error) {
	accessToken, err := g.fetchAccessToken(ctx, code)
	if err != nil {
		return "", fmt.Errorf("github exchange: %w", err)
	}
	login, err := g.fetchLogin(ctx, accessToken)
	if err != nil {
		return "", fmt.Errorf("github exchange: %w", err)
	}
	return login + "@github", nil
}

func (g *GitHubProvider) fetchAccessToken(ctx context.Context, code string) (string, error) {
	body := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"redirect_uri":  {g.callbackURL},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL,
		strings.NewReader(body.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch access token: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("github oauth error: %s", result.Error)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("github returned empty access token")
	}
	return result.AccessToken, nil
}

func (g *GitHubProvider) fetchLogin(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	if err != nil {
		return "", fmt.Errorf("build user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch github user: %w", err)
	}
	defer resp.Body.Close()

	var user struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("decode user response: %w", err)
	}
	if user.Login == "" {
		return "", fmt.Errorf("github returned empty login")
	}
	return user.Login, nil
}
