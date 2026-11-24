import { z } from 'zod';

/**
 * Zod runtime schemas and validation guards for Cloudflare Workers AI outputs.
 * Protects frontend state against LLM hallucinations, schema drift, and boundary violations.
 */

export const AIOpsMapDataSchema = z.object({
  T1: z.number().default(0),
  T2: z.number().default(0),
  T3: z.number().default(0),
  W1: z.tuple([z.number(), z.number()]).nullable().default(null),
  W2: z.tuple([z.number(), z.number()]).nullable().default(null),
  W3: z.tuple([z.number(), z.number()]).nullable().default(null),
  w2_colo: z.string().default(''),
  flag_1: z.boolean().default(false),
  flag_2: z.boolean().default(false),
  flag_route_1: z.boolean().default(false),
  flag_route_2: z.boolean().default(false),
  W1_label: z.string().default(''),
  W2_label: z.string().default(''),
  W3_label: z.string().default('')
});

export const AIOpsInfluenceItemSchema = z.object({
  object: z.string().default('Service Impact'),
  severity: z.string().default('🔴'),
  content: z.string().default('')
});

export const AIOpsInsightSchema = z.object({
  sloBudgetImpact: z.string().default(''),
  w1Colo: z.string().default(''),
  w2Colo: z.string().default(''),
  w3Ip: z.string().default(''),
  packetLoss: z.string().default('0%'),
  influence: z.array(AIOpsInfluenceItemSchema).default([]),
  secondaryRisks: z.string().default(''),
  suggestion: z.string().default('')
});

export const AIOpsResponseSchema = z.object({
  error_code: z.enum(['INCOMPLETE_PARAM', 'SECURITY_VIOLATION', 'OUT_OF_SCOPE']).nullable().default(null),
  error_message: z.string().nullable().default(null),
  warning_code: z.enum(['LOGICAL_CONFLICT', 'CORRECTION_WARNING']).nullable().default(null),
  warning_message: z.string().nullable().default(null),
  map_data: AIOpsMapDataSchema.nullable().default(null),
  insight: AIOpsInsightSchema.nullable().default(null)
});

export type AIOpsResponse = z.infer<typeof AIOpsResponseSchema>;

export const AutoFillDataSchema = z.object({
  targetHostname: z.string().default(''),
  scope: z.enum(['Global', 'Cloud ASNs', 'Cellular', 'Cross-Region', 'Bots Only']).default('Global'),
  tokenTtl: z.number().min(1).max(10080).default(60),
  faultType: z.enum(['latency', '502', '504', '429', '444']).default('latency'),
  distribution: z.enum(['Uniform', 'Normal', 'Spikes']).nullable().default(null),
  baseLatency: z.number().int().min(0).max(60000).nullable().default(null),
  jitter: z.number().min(0).max(60000).nullable().default(null),
  packetLoss: z.number().min(0).max(100).nullable().default(null),
  mutilationStrategy: z.enum(['None', 'Unexpected EOF', 'Type Poisoning', 'Empty Shell']).default('None')
});

export const AutoFillResponseSchema = z.object({
  status: z.enum(['success', 'warning', 'error']).default('success'),
  conflict_reason: z.string().nullable().default(null),
  resolution: z.string().nullable().default(null),
  error_message: z.string().nullable().default(null),
  data: AutoFillDataSchema.nullable().default(null)
});

export type AutoFillResponse = z.infer<typeof AutoFillResponseSchema>;

/**
 * Validates and sanitizes AIOps Engine LLM outputs.
 */
export function validateAIOpsResponse(raw: unknown): AIOpsResponse {
  const result = AIOpsResponseSchema.safeParse(raw);
  if (result.success) {
    return result.data;
  }
  console.warn('[AI Schema Guard] AIOps response failed schema validation:', result.error.format());
  return {
    error_code: 'OUT_OF_SCOPE',
    error_message: 'The Engine response failed strict schema validation guardrails.',
    warning_code: null,
    warning_message: null,
    map_data: null,
    insight: null
  };
}

/**
 * Validates and sanitizes AutoFill Engine LLM outputs.
 */
export function validateAutoFillResponse(raw: unknown): AutoFillResponse {
  const result = AutoFillResponseSchema.safeParse(raw);
  if (result.success) {
    return result.data;
  }
  console.warn('[AI Schema Guard] AutoFill response failed schema validation:', result.error.format());
  return {
    status: 'error',
    conflict_reason: null,
    resolution: null,
    error_message: 'The generated parameters violated strict runtime schema boundaries.',
    data: null
  };
}
