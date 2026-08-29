export class SessionStore {
  private readonly sessionApprovals = new Set<string>();

  /**
   * Generates a unique key for session approval
   */
  private makeKey(operation: string, relativePath: string): string {
    return `${operation.toUpperCase()}:${relativePath.toLowerCase().replace(/\\/g, '/')}`;
  }

  grant(operation: string, relativePath: string): void {
    this.sessionApprovals.add(this.makeKey(operation, relativePath));
  }

  isApproved(operation: string, relativePath: string): boolean {
    return this.sessionApprovals.has(this.makeKey(operation, relativePath));
  }

  clear(): void {
    this.sessionApprovals.clear();
  }
}
