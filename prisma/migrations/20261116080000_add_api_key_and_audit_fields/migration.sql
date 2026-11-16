-- AlterTable
ALTER TABLE "User" ADD COLUMN "apiKeyHash" TEXT;
ALTER TABLE "User" ADD COLUMN "apiKeyPrefix" TEXT;
ALTER TABLE "User" ADD COLUMN "apiKeyCreatedAt" DATETIME;

-- CreateIndex
CREATE UNIQUE INDEX "User_apiKeyHash_key" ON "User"("apiKeyHash");

-- AlterTable
ALTER TABLE "ChaosLog" ADD COLUMN "source" TEXT NOT NULL DEFAULT 'DIRECT_DATA_PLANE';
ALTER TABLE "ChaosLog" ADD COLUMN "tokenId" TEXT;
ALTER TABLE "ChaosLog" ADD COLUMN "tokenHint" TEXT;
ALTER TABLE "ChaosLog" ADD COLUMN "edgeColo" TEXT;
ALTER TABLE "ChaosLog" ADD COLUMN "statusCode" INTEGER;
ALTER TABLE "ChaosLog" ADD COLUMN "latencyMs" INTEGER;
ALTER TABLE "ChaosLog" ADD COLUMN "rayId" TEXT;

-- CreateIndex
CREATE INDEX "ChaosLog_userId_source_idx" ON "ChaosLog"("userId", "source");
