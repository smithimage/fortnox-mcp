import axios, { AxiosError } from "axios";
import { FORTNOX_OAUTH_URL, TOKEN_REFRESH_BUFFER_MS } from "../constants.js";
import { ITokenProvider, TokenInfo, AuthRequiredError } from "./types.js";
import { getFortnoxCredentials } from "./credentials.js";
import { getFileStorage } from "./storage/file.js";

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

const FILE_STORAGE_USER_ID = "local";

// Local mode token provider
// Supports optional file-based token persistence via FORTNOX_TOKEN_FILE env var.
// This allows tokens to survive across process restarts and enables external
// tools (like a renewal skill) to inject fresh tokens into a running server.
export class EnvVarTokenProvider implements ITokenProvider {
  private clientId: string;
  private clientSecret: string;
  private tokens: TokenInfo | null = null;
  private refreshPromise: Promise<string> | null = null;

  constructor() {
    const { clientId, clientSecret } = getFortnoxCredentials();
    this.clientId = clientId;
    this.clientSecret = clientSecret;

    // Initialize from environment if tokens provided
    const refreshToken = process.env.FORTNOX_REFRESH_TOKEN;
    const accessToken = process.env.FORTNOX_ACCESS_TOKEN;

    if (refreshToken) {
      this.tokens = {
        accessToken: accessToken || "",
        refreshToken: refreshToken,
        expiresAt: accessToken ? Date.now() + 3600000 : 0,
        scope: process.env.FORTNOX_SCOPE || ""
      };
    }

    // Try loading from file storage (may have fresher tokens than env vars)
    this.loadFromFileStorage();
  }

  /**
   * Check file storage for tokens that may be newer than the env var ones.
   * This covers two cases:
   * 1. The env var token expired but a previous run persisted a fresh one
   * 2. An external tool (skill) wrote a fresh token to the file
   */
  private loadFromFileStorage(): void {
    const fileStorage = getFileStorage();
    if (!fileStorage) return;

    // Synchronous-ish: getFileStorage reads synchronously under the hood
    fileStorage.get(FILE_STORAGE_USER_ID).then(stored => {
      if (stored?.refreshToken) {
        // File tokens take precedence if they exist — they're likely fresher
        // than the env var which was set at process start
        console.error("[Auth] Loaded tokens from file storage");
        this.tokens = stored;
      }
    }).catch(() => {
      // Ignore file read errors, fall back to env vars
    });
  }

  /**
   * Persist tokens to file storage so they survive restarts and can be
   * picked up if the env var becomes stale.
   */
  private persistToFileStorage(): void {
    const fileStorage = getFileStorage();
    if (!fileStorage || !this.tokens) return;

    fileStorage.set(FILE_STORAGE_USER_ID, this.tokens).catch(err => {
      console.error("[Auth] Failed to persist tokens to file:", err);
    });
  }

  async getAccessToken(_userId?: string): Promise<string> {
    if (!this.tokens) {
      throw new AuthRequiredError();
    }

    const needsRefresh = Date.now() >= this.tokens.expiresAt - TOKEN_REFRESH_BUFFER_MS;

    if (needsRefresh || !this.tokens.accessToken) {
      if (!this.refreshPromise) {
        this.refreshPromise = this.refreshAccessToken().finally(() => {
          this.refreshPromise = null;
        });
      }
      return this.refreshPromise;
    }

    return this.tokens.accessToken;
  }

  isAuthenticated(_userId?: string): boolean {
    return this.tokens !== null && this.tokens.refreshToken !== "";
  }

  getTokenInfo(_userId?: string): TokenInfo | null {
    return this.tokens;
  }

  async exchangeAuthorizationCode(code: string, redirectUri: string): Promise<void> {
    const tokenUrl = `${FORTNOX_OAUTH_URL}/token`;
    const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");

    try {
      const response = await axios.post<TokenResponse>(
        tokenUrl,
        new URLSearchParams({
          grant_type: "authorization_code",
          code: code,
          redirect_uri: redirectUri
        }),
        {
          headers: {
            "Authorization": `Basic ${auth}`,
            "Content-Type": "application/x-www-form-urlencoded"
          }
        }
      );

      this.storeTokens(response.data);
    } catch (error) {
      throw this.handleAuthError(error, "Failed to exchange authorization code");
    }
  }

  getAuthorizationUrl(redirectUri: string, scopes: string[], state?: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(" "),
      response_type: "code",
      access_type: "offline"
    });

    if (state) {
      params.set("state", state);
    }

    return `${FORTNOX_OAUTH_URL}/auth?${params.toString()}`;
  }

  private async refreshAccessToken(): Promise<string> {
    if (!this.tokens?.refreshToken) {
      // Last resort: check file storage for externally-injected tokens
      const fileTokens = await this.tryLoadFromFileStorage();
      if (fileTokens?.refreshToken) {
        this.tokens = fileTokens;
      } else {
        throw new Error("No refresh token available");
      }
    }

    const tokenUrl = `${FORTNOX_OAUTH_URL}/token`;
    const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");

    try {
      const response = await axios.post<TokenResponse>(
        tokenUrl,
        new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: this.tokens.refreshToken
        }),
        {
          headers: {
            "Authorization": `Basic ${auth}`,
            "Content-Type": "application/x-www-form-urlencoded"
          }
        }
      );

      this.storeTokens(response.data);
      return this.tokens!.accessToken;
    } catch (error) {
      // If refresh failed, try file storage — an external tool may have
      // written a fresh token since we last checked
      const fileTokens = await this.tryLoadFromFileStorage();
      if (fileTokens?.refreshToken && fileTokens.refreshToken !== this.tokens?.refreshToken) {
        console.error("[Auth] Env token refresh failed, trying file storage token...");
        this.tokens = fileTokens;
        // Retry once with the file-based token
        try {
          const retryResponse = await axios.post<TokenResponse>(
            tokenUrl,
            new URLSearchParams({
              grant_type: "refresh_token",
              refresh_token: this.tokens.refreshToken
            }),
            {
              headers: {
                "Authorization": `Basic ${auth}`,
                "Content-Type": "application/x-www-form-urlencoded"
              }
            }
          );
          this.storeTokens(retryResponse.data);
          return this.tokens!.accessToken;
        } catch (retryError) {
          this.tokens = null;
          throw this.handleAuthError(retryError, "Failed to refresh access token");
        }
      }

      this.tokens = null;
      throw this.handleAuthError(error, "Failed to refresh access token");
    }
  }

  private async tryLoadFromFileStorage(): Promise<TokenInfo | null> {
    const fileStorage = getFileStorage();
    if (!fileStorage) return null;
    try {
      return await fileStorage.get(FILE_STORAGE_USER_ID);
    } catch {
      return null;
    }
  }

  private storeTokens(response: TokenResponse): void {
    this.tokens = {
      accessToken: response.access_token,
      refreshToken: response.refresh_token,
      expiresAt: Date.now() + response.expires_in * 1000,
      scope: response.scope
    };
    this.persistToFileStorage();
  }

  private handleAuthError(error: unknown, context: string): Error {
    if (error instanceof AxiosError) {
      const status = error.response?.status;
      const data = error.response?.data;

      if (status === 401) {
        return new Error(
          `${context}: Invalid credentials. Check FORTNOX_CLIENT_ID and FORTNOX_CLIENT_SECRET.`
        );
      }
      if (status === 400) {
        const errorDesc = data?.error_description || data?.error || "Bad request";
        return new Error(
          `${context}: ${errorDesc}. The refresh token may be expired or revoked. ` +
          `Please re-authorize the application.`
        );
      }
      return new Error(
        `${context}: API error ${status} - ${JSON.stringify(data)}`
      );
    }

    return new Error(`${context}: ${error instanceof Error ? error.message : String(error)}`);
  }
}
