-- CreateIndex for Token performance and N+1 full scan elimination
CREATE INDEX IF NOT EXISTS "Token_userId_isRevoked_idx" ON "Token"("userId", "isRevoked");
CREATE INDEX IF NOT EXISTS "Token_userId_createdAt_idx" ON "Token"("userId", "createdAt");
