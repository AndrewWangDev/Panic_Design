import { describe, it, expect } from 'vitest';
import {
  AIOpsResponseSchema,
  AutoFillResponseSchema,
  validateAIOpsResponse,
  validateAutoFillResponse
} from '../src/lib/ai-schema';

describe('AI Schema Runtime Validation Guard (SEC-05)', () => {
  describe('AIOps Schema Validation', () => {
    it('should validate and parse a legitimate AIOps response', () => {
      const validPayload = {
        error_code: null,
        error_message: null,
        warning_code: null,
        warning_message: null,
        map_data: {
          T1: 25,
          T2: 1000,
          T3: 15,
          W1: [-122.39, 37.77],
          W2: [-121.89, 37.34],
          W3: [139.69, 35.69],
          w2_colo: 'SJC',
          flag_1: false,
          flag_2: true,
          flag_route_1: false,
          flag_route_2: true,
          W1_label: '',
          W2_label: 'Latency Injection',
          W3_label: ''
        },
        insight: {
          sloBudgetImpact: 'P99 latency increases by 1000ms',
          w1Colo: 'SFO',
          w2Colo: 'SJC',
          w3Ip: '1.1.1.1',
          packetLoss: '0%',
          influence: [
            {
              object: 'API Gateway',
              severity: '🔴',
              content: 'Elevated response latency exceeding 1s'
            }
          ],
          secondaryRisks: 'Thread pool exhaustion downstream',
          suggestion: 'Increase client timeout or tune connection pool'
        }
      };

      const result = validateAIOpsResponse(validPayload);
      expect(result.error_code).toBeNull();
      expect(result.map_data?.T2).toBe(1000);
      expect(result.map_data?.w2_colo).toBe('SJC');
      expect(result.insight?.influence).toHaveLength(1);
    });

    it('should safely guard against hallucinated or malformed fields by falling back to OUT_OF_SCOPE', () => {
      const malformedPayload = {
        error_code: 'INVALID_ERROR_ENUM_NOT_ALLOWED',
        map_data: 'string instead of object'
      };

      const result = validateAIOpsResponse(malformedPayload);
      expect(result.error_code).toBe('OUT_OF_SCOPE');
      expect(result.error_message).toContain('failed strict schema validation');
      expect(result.map_data).toBeNull();
    });
  });

  describe('AutoFill Schema Validation', () => {
    it('should validate a valid AutoFill configuration', () => {
      const validPayload = {
        status: 'success',
        conflict_reason: null,
        resolution: null,
        error_message: null,
        data: {
          targetHostname: 'api.example.com',
          scope: 'Global',
          tokenTtl: 60,
          faultType: '502',
          distribution: null,
          baseLatency: null,
          jitter: null,
          packetLoss: null,
          mutilationStrategy: 'None'
        }
      };

      const result = validateAutoFillResponse(validPayload);
      expect(result.status).toBe('success');
      expect(result.data?.faultType).toBe('502');
      expect(result.data?.tokenTtl).toBe(60);
    });

    it('should reject out-of-range numerical values (e.g. packetLoss > 100 or negative TTL)', () => {
      const outOfRangePayload = {
        status: 'success',
        data: {
          targetHostname: 'api.example.com',
          scope: 'Global',
          tokenTtl: -10, // Invalid: min is 1
          faultType: 'latency',
          distribution: 'Uniform',
          baseLatency: 500,
          jitter: 50,
          packetLoss: 150, // Invalid: max is 100
          mutilationStrategy: 'None'
        }
      };

      const result = validateAutoFillResponse(outOfRangePayload);
      expect(result.status).toBe('error');
      expect(result.error_message).toContain('runtime schema boundaries');
      expect(result.data).toBeNull();
    });

    it('should reject invalid faultType enums', () => {
      const invalidEnumPayload = {
        status: 'success',
        data: {
          targetHostname: 'api.example.com',
          scope: 'Global',
          tokenTtl: 30,
          faultType: 'DROP_DATABASE', // Malicious or hallucinated enum
          distribution: null,
          baseLatency: null,
          jitter: null,
          packetLoss: null,
          mutilationStrategy: 'None'
        }
      };

      const result = validateAutoFillResponse(invalidEnumPayload);
      expect(result.status).toBe('error');
      expect(result.data).toBeNull();
    });
  });
});
