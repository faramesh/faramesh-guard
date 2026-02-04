/**
 * Fail-Closed Policy - Client-Side Protection
 * ============================================
 *
 * Implements fail-closed behavior when the Guard daemon is unreachable.
 *
 * From guard-plan-v1.md:
 * - Block exec/write/delete/post when daemon unreachable
 * - Allow read/get/status operations (safe)
 * - Circuit breaker pattern
 * - Automatic recovery when daemon becomes available
 *
 * Usage:
 *   import { FailClosedPolicy, ActionType } from './fail-closed';
 *
 *   const policy = new FailClosedPolicy();
 *
 *   // Check if action should be blocked
 *   const result = await policy.shouldBlock(ActionType.EXECUTE);
 *   if (result.blocked) {
 *     console.log(`Action blocked: ${result.reason}`);
 *   }
 */

import { EventEmitter } from 'events';

/**
 * Types of actions that can be intercepted
 */
export enum ActionType {
  // Dangerous actions - blocked when disconnected
  EXECUTE = 'execute',
  WRITE = 'write',
  DELETE = 'delete',
  POST = 'post',
  PUT = 'put',
  PATCH = 'patch',

  // Safe actions - allowed when disconnected
  READ = 'read',
  GET = 'get',
  STATUS = 'status',
  LIST = 'list',
  SEARCH = 'search',
  HEALTH = 'health',
}

/**
 * Connection state to the Guard daemon
 */
export enum ConnectionState {
  CONNECTED = 'connected',
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  DEGRADED = 'degraded',
}

/**
 * Circuit breaker state
 */
export enum CircuitState {
  CLOSED = 'closed',     // Normal operation
  OPEN = 'open',         // Blocking all requests
  HALF_OPEN = 'half_open', // Testing recovery
}

/**
 * Result of a fail-closed check
 */
export interface FailClosedResult {
  blocked: boolean;
  reason: string;
  actionType: ActionType;
  connectionState: ConnectionState;
  circuitState: CircuitState;
  canRetry: boolean;
  retryAfterMs?: number;
}

/**
 * Statistics for monitoring
 */
export interface FailClosedStats {
  totalChecks: number;
  blockedCount: number;
  allowedCount: number;
  connectionAttempts: number;
  lastConnectedAt?: Date;
  lastDisconnectedAt?: Date;
  consecutiveFailures: number;
  circuitBreakerTrips: number;
}

/**
 * Configuration options
 */
export interface FailClosedConfig {
  /** Daemon URL */
  daemonUrl: string;

  /** Health check endpoint */
  healthEndpoint: string;

  /** Health check interval in ms */
  healthCheckIntervalMs: number;

  /** Connection timeout in ms */
  connectionTimeoutMs: number;

  /** Number of failures before circuit opens */
  circuitBreakerThreshold: number;

  /** Time to wait before trying half-open */
  circuitBreakerResetMs: number;

  /** Maximum time to block before giving up */
  maxBlockTimeMs: number;

  /** Allow read operations when disconnected */
  allowReadWhenDisconnected: boolean;

  /** Log blocked actions */
  logBlocked: boolean;
}

const DEFAULT_CONFIG: FailClosedConfig = {
  daemonUrl: 'http://127.0.0.1:8765',
  healthEndpoint: '/health',
  healthCheckIntervalMs: 5000,  // 5 seconds
  connectionTimeoutMs: 3000,    // 3 seconds
  circuitBreakerThreshold: 3,   // 3 failures to trip
  circuitBreakerResetMs: 30000, // 30 seconds before half-open
  maxBlockTimeMs: 60000,        // 60 seconds max block
  allowReadWhenDisconnected: true,
  logBlocked: true,
};

/**
 * Actions classified as dangerous (blocked when disconnected)
 */
const DANGEROUS_ACTIONS: Set<ActionType> = new Set([
  ActionType.EXECUTE,
  ActionType.WRITE,
  ActionType.DELETE,
  ActionType.POST,
  ActionType.PUT,
  ActionType.PATCH,
]);

/**
 * Actions classified as safe (allowed when disconnected)
 */
const SAFE_ACTIONS: Set<ActionType> = new Set([
  ActionType.READ,
  ActionType.GET,
  ActionType.STATUS,
  ActionType.LIST,
  ActionType.SEARCH,
  ActionType.HEALTH,
]);

/**
 * FailClosedPolicy - Blocks dangerous operations when Guard daemon is unreachable
 */
export class FailClosedPolicy extends EventEmitter {
  private config: FailClosedConfig;
  private connectionState: ConnectionState;
  private circuitState: CircuitState;
  private consecutiveFailures: number;
  private lastHealthCheck?: Date;
  private lastSuccessfulConnection?: Date;
  private lastDisconnection?: Date;
  private circuitOpenedAt?: Date;
  private healthCheckInterval?: NodeJS.Timeout;
  private stats: FailClosedStats;
  private pendingHealthCheck: boolean;

  constructor(config: Partial<FailClosedConfig> = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.connectionState = ConnectionState.DISCONNECTED;
    this.circuitState = CircuitState.CLOSED;
    this.consecutiveFailures = 0;
    this.pendingHealthCheck = false;
    this.stats = {
      totalChecks: 0,
      blockedCount: 0,
      allowedCount: 0,
      connectionAttempts: 0,
      consecutiveFailures: 0,
      circuitBreakerTrips: 0,
    };
  }

  /**
   * Start the fail-closed policy (begins health checks)
   */
  async start(): Promise<void> {
    // Do initial health check
    await this.performHealthCheck();

    // Start periodic health checks
    this.healthCheckInterval = setInterval(
      () => this.performHealthCheck(),
      this.config.healthCheckIntervalMs
    );

    this.emit('started');
    console.log('[FailClosedPolicy] Started with config:', this.config);
  }

  /**
   * Stop the fail-closed policy
   */
  stop(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = undefined;
    }
    this.emit('stopped');
    console.log('[FailClosedPolicy] Stopped');
  }

  /**
   * Perform a health check against the daemon
   */
  private async performHealthCheck(): Promise<boolean> {
    if (this.pendingHealthCheck) {
      return false;
    }

    this.pendingHealthCheck = true;
    this.stats.connectionAttempts++;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        this.config.connectionTimeoutMs
      );

      const response = await fetch(
        `${this.config.daemonUrl}${this.config.healthEndpoint}`,
        {
          method: 'GET',
          signal: controller.signal,
        }
      );

      clearTimeout(timeoutId);

      if (response.ok) {
        this.onConnectionSuccess();
        return true;
      } else {
        this.onConnectionFailure(`HTTP ${response.status}`);
        return false;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      this.onConnectionFailure(message);
      return false;
    } finally {
      this.pendingHealthCheck = false;
      this.lastHealthCheck = new Date();
    }
  }

  /**
   * Handle successful connection
   */
  private onConnectionSuccess(): void {
    const wasDisconnected = this.connectionState !== ConnectionState.CONNECTED;

    this.connectionState = ConnectionState.CONNECTED;
    this.consecutiveFailures = 0;
    this.lastSuccessfulConnection = new Date();
    this.stats.consecutiveFailures = 0;

    // Reset circuit breaker
    if (this.circuitState !== CircuitState.CLOSED) {
      this.circuitState = CircuitState.CLOSED;
      this.emit('circuit:closed');
    }

    if (wasDisconnected) {
      this.emit('connected');
      console.log('[FailClosedPolicy] Daemon connected');
    }
  }

  /**
   * Handle connection failure
   */
  private onConnectionFailure(reason: string): void {
    this.consecutiveFailures++;
    this.stats.consecutiveFailures = this.consecutiveFailures;

    const wasConnected = this.connectionState === ConnectionState.CONNECTED;

    // Update connection state
    if (this.connectionState === ConnectionState.CONNECTED) {
      this.connectionState = ConnectionState.DISCONNECTED;
      this.lastDisconnection = new Date();
      this.stats.lastDisconnectedAt = this.lastDisconnection;
      this.emit('disconnected', reason);
      console.warn(`[FailClosedPolicy] Daemon disconnected: ${reason}`);
    }

    // Check circuit breaker threshold
    if (this.consecutiveFailures >= this.config.circuitBreakerThreshold) {
      if (this.circuitState === CircuitState.CLOSED) {
        this.tripCircuitBreaker();
      }
    }
  }

  /**
   * Trip the circuit breaker (block all dangerous operations)
   */
  private tripCircuitBreaker(): void {
    this.circuitState = CircuitState.OPEN;
    this.circuitOpenedAt = new Date();
    this.stats.circuitBreakerTrips++;
    this.emit('circuit:open');
    console.warn('[FailClosedPolicy] Circuit breaker OPENED - blocking dangerous operations');

    // Schedule half-open attempt
    setTimeout(() => {
      if (this.circuitState === CircuitState.OPEN) {
        this.circuitState = CircuitState.HALF_OPEN;
        this.emit('circuit:half-open');
        console.log('[FailClosedPolicy] Circuit breaker HALF-OPEN - testing recovery');
        this.performHealthCheck();
      }
    }, this.config.circuitBreakerResetMs);
  }

  /**
   * Check if an action type is dangerous
   */
  isDangerousAction(actionType: ActionType): boolean {
    return DANGEROUS_ACTIONS.has(actionType);
  }

  /**
   * Check if an action type is safe
   */
  isSafeAction(actionType: ActionType): boolean {
    return SAFE_ACTIONS.has(actionType);
  }

  /**
   * Classify an HTTP method as an ActionType
   */
  classifyHttpMethod(method: string): ActionType {
    const upper = method.toUpperCase();
    switch (upper) {
      case 'GET':
        return ActionType.GET;
      case 'POST':
        return ActionType.POST;
      case 'PUT':
        return ActionType.PUT;
      case 'PATCH':
        return ActionType.PATCH;
      case 'DELETE':
        return ActionType.DELETE;
      default:
        return ActionType.GET;
    }
  }

  /**
   * Check if an action should be blocked
   */
  async shouldBlock(actionType: ActionType): Promise<FailClosedResult> {
    this.stats.totalChecks++;

    const result: FailClosedResult = {
      blocked: false,
      reason: '',
      actionType,
      connectionState: this.connectionState,
      circuitState: this.circuitState,
      canRetry: false,
    };

    // If connected, allow everything
    if (this.connectionState === ConnectionState.CONNECTED) {
      result.blocked = false;
      result.reason = 'Daemon connected';
      this.stats.allowedCount++;
      return result;
    }

    // If disconnected, check action type
    if (this.isSafeAction(actionType)) {
      if (this.config.allowReadWhenDisconnected) {
        result.blocked = false;
        result.reason = 'Safe action allowed while disconnected';
        this.stats.allowedCount++;
        return result;
      }
    }

    // Dangerous action while disconnected
    if (this.isDangerousAction(actionType)) {
      result.blocked = true;
      result.reason = 'Dangerous action blocked - Guard daemon unreachable';
      result.canRetry = true;
      result.retryAfterMs = this.config.healthCheckIntervalMs;
      this.stats.blockedCount++;

      if (this.config.logBlocked) {
        console.warn(`[FailClosedPolicy] BLOCKED: ${actionType} - daemon unreachable`);
        this.emit('blocked', { actionType, reason: result.reason });
      }

      return result;
    }

    // Unknown action - block by default (fail-closed)
    result.blocked = true;
    result.reason = 'Unknown action type blocked - fail-closed policy';
    result.canRetry = true;
    result.retryAfterMs = this.config.healthCheckIntervalMs;
    this.stats.blockedCount++;

    return result;
  }

  /**
   * Block until daemon is available or timeout
   */
  async waitForConnection(timeoutMs?: number): Promise<boolean> {
    const timeout = timeoutMs || this.config.maxBlockTimeMs;
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      if (this.connectionState === ConnectionState.CONNECTED) {
        return true;
      }

      // Try a health check
      const success = await this.performHealthCheck();
      if (success) {
        return true;
      }

      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    return false;
  }

  /**
   * Get current connection state
   */
  getConnectionState(): ConnectionState {
    return this.connectionState;
  }

  /**
   * Get current circuit state
   */
  getCircuitState(): CircuitState {
    return this.circuitState;
  }

  /**
   * Check if currently connected
   */
  isConnected(): boolean {
    return this.connectionState === ConnectionState.CONNECTED;
  }

  /**
   * Get statistics
   */
  getStats(): FailClosedStats {
    return {
      ...this.stats,
      lastConnectedAt: this.lastSuccessfulConnection,
      lastDisconnectedAt: this.lastDisconnection,
    };
  }

  /**
   * Force a health check
   */
  async forceHealthCheck(): Promise<boolean> {
    return this.performHealthCheck();
  }

  /**
   * Reset circuit breaker (manual override)
   */
  resetCircuitBreaker(): void {
    this.circuitState = CircuitState.CLOSED;
    this.consecutiveFailures = 0;
    this.stats.consecutiveFailures = 0;
    this.emit('circuit:reset');
    console.log('[FailClosedPolicy] Circuit breaker manually reset');
  }
}

// Singleton instance
let globalFailClosedPolicy: FailClosedPolicy | null = null;

/**
 * Get or create the global FailClosedPolicy instance
 */
export function getFailClosedPolicy(config?: Partial<FailClosedConfig>): FailClosedPolicy {
  if (!globalFailClosedPolicy) {
    globalFailClosedPolicy = new FailClosedPolicy(config);
  }
  return globalFailClosedPolicy;
}

/**
 * Reset the global FailClosedPolicy instance
 */
export function resetFailClosedPolicy(config?: Partial<FailClosedConfig>): FailClosedPolicy {
  if (globalFailClosedPolicy) {
    globalFailClosedPolicy.stop();
  }
  globalFailClosedPolicy = new FailClosedPolicy(config);
  return globalFailClosedPolicy;
}

/**
 * Decorator/wrapper for protecting async functions with fail-closed policy
 */
export function withFailClosed(actionType: ActionType) {
  return function<T extends (...args: any[]) => Promise<any>>(
    target: any,
    propertyKey: string,
    descriptor: TypedPropertyDescriptor<T>
  ): TypedPropertyDescriptor<T> {
    const originalMethod = descriptor.value!;

    descriptor.value = async function(this: any, ...args: any[]): Promise<any> {
      const policy = getFailClosedPolicy();
      const result = await policy.shouldBlock(actionType);

      if (result.blocked) {
        throw new Error(`Action blocked by fail-closed policy: ${result.reason}`);
      }

      return originalMethod.apply(this, args);
    } as T;

    return descriptor;
  };
}

export default FailClosedPolicy;
