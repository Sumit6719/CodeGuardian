# CodeGuardian Capabilities Framework

CodeGuardian governs execution parameters using structured capability grants (`CapabilityGrant`). 

## Concept

Instead of executing raw commands directly, CodeGuardian generates a bounded privilege set based on security policies. The executor verifies that the proposed execution parameters fit within the granted capabilities.

```text
Action Proposal
      ↓
Deterministic Evaluation
      ↓
Capability Grant (Issued)
      ↓
Execution Validation (Enforced)
```

## Capability Schema

```typescript
export interface CapabilityGrant {
  readonly id: string;                  // Unique Capability identifier
  readonly operation: OperationType;    // Governed action operation type
  readonly workspaceRoot: string;       // Confined workspace folder
  readonly allowedPaths: string[];      // Path regions allowed for read/write
  readonly deniedPaths: string[];       // Path regions denied for operations
  readonly network: 'NONE' | 'LIMITED' | 'FULL';
  readonly processExecution: boolean;   // True if process spawning is allowed
  readonly maxExecutionTimeMs: number;  // Spawning process timeout gate limit
  readonly maxOutputBytes: number;      // Maximum captured bytes cap
  readonly grantedAt: number;           // Issuance timestamp
  readonly expiresAt: number;           // Expiration bounds
}
```

## Execution Hardening Rules

1. **Path Enforcement**: The working directory and file operations are strictly verified against `allowedPaths` and `deniedPaths`.
2. **Buffer Bounds**: Captured standard output (`stdout`) and standard error (`stderr`) streams are truncated when exceeding `maxOutputBytes` to prevent memory exhaustion.
3. **Execution Limits**: Processes are killed recursively if execution duration exceeds `maxExecutionTimeMs`.
4. **AI Separation**: The capability is generated deterministically by CodeGuardian. The AI agent cannot configure, expand, or elevate the Capability Grant parameters.
