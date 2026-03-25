import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { dirname } from "path";
import { TokenInfo } from "../types.js";
import { ITokenStorage, StoredTokenInfo } from "./types.js";

/**
 * File-based token storage
 *
 * Persists tokens to a JSON file on disk. This is particularly useful in
 * environments where environment variables are read-only after process start
 * (e.g., Cowork mode), but a writable cache directory exists.
 *
 * The file path is configured via FORTNOX_TOKEN_FILE env var.
 */
export class FileTokenStorage implements ITokenStorage {
  private filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  async get(userId: string): Promise<TokenInfo | null> {
    try {
      if (!existsSync(this.filePath)) return null;
      const data = JSON.parse(readFileSync(this.filePath, "utf-8"));
      const stored = data[userId];
      if (!stored) return null;

      return {
        accessToken: stored.accessToken || "",
        refreshToken: stored.refreshToken,
        expiresAt: stored.expiresAt || 0,
        scope: stored.scope || ""
      };
    } catch {
      return null;
    }
  }

  async set(userId: string, tokens: TokenInfo): Promise<void> {
    let data: Record<string, StoredTokenInfo> = {};
    try {
      if (existsSync(this.filePath)) {
        data = JSON.parse(readFileSync(this.filePath, "utf-8"));
      }
    } catch {
      // Start fresh if file is corrupted
    }

    const existing = data[userId];
    const now = Date.now();

    data[userId] = {
      ...tokens,
      createdAt: existing?.createdAt || now,
      updatedAt: now
    };

    // Ensure directory exists
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    writeFileSync(this.filePath, JSON.stringify(data, null, 2), "utf-8");
  }

  async delete(userId: string): Promise<void> {
    try {
      if (!existsSync(this.filePath)) return;
      const data = JSON.parse(readFileSync(this.filePath, "utf-8"));
      delete data[userId];
      writeFileSync(this.filePath, JSON.stringify(data, null, 2), "utf-8");
    } catch {
      // Ignore errors on delete
    }
  }

  async exists(userId: string): Promise<boolean> {
    const tokens = await this.get(userId);
    return tokens !== null;
  }
}

// Singleton based on env var
let fileStorage: FileTokenStorage | null = null;

export function getFileStorage(): FileTokenStorage | null {
  const filePath = process.env.FORTNOX_TOKEN_FILE;
  if (!filePath) return null;

  if (!fileStorage) {
    fileStorage = new FileTokenStorage(filePath);
  }
  return fileStorage;
}
