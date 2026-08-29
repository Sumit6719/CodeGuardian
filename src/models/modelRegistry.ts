import { IModelProvider } from './provider.interface.js';

export class ModelProviderRegistry {
  private readonly providers = new Map<string, IModelProvider>();

  constructor(initialProviders?: IModelProvider[]) {
    if (initialProviders) {
      for (const p of initialProviders) {
        this.registerProvider(p);
      }
    }
  }

  /**
   * Registers a model provider instance. Rejects duplicate provider IDs.
   */
  registerProvider(provider: IModelProvider): void {
    if (!provider) return;
    const providerId = provider.providerId || provider.name || 'unknown';
    const pid = providerId.toLowerCase();
    if (this.providers.has(pid)) {
      throw new Error(`ModelProviderRegistry error: Provider with ID "${providerId}" is already registered.`);
    }
    this.providers.set(pid, provider);
  }

  /**
   * Unregisters a provider by providerId.
   */
  unregisterProvider(providerId: string): boolean {
    if (!providerId) return false;
    return this.providers.delete(providerId.toLowerCase());
  }

  /**
   * Retrieves a registered provider by providerId.
   */
  getProvider(providerId: string): IModelProvider | undefined {
    if (!providerId) return undefined;
    return this.providers.get(providerId.toLowerCase());
  }

  /**
   * Returns all registered providers regardless of configuration state.
   */
  getAllProviders(): readonly IModelProvider[] {
    return Array.from(this.providers.values());
  }

  /**
   * Returns all providers that report isConfigured() === true.
   */
  getConfiguredProviders(): readonly IModelProvider[] {
    return Array.from(this.providers.values()).filter(p => typeof p.isConfigured === 'function' ? p.isConfigured() : true);
  }

  /**
   * Selects a provider by ID if configured, or falls back to first configured provider.
   */
  selectProvider(preferredProviderId?: string): IModelProvider {
    if (preferredProviderId) {
      const p = this.getProvider(preferredProviderId);
      if (p && p.isConfigured()) {
        return p;
      }
    }

    const configured = this.getConfiguredProviders();
    if (configured.length === 0) {
      throw new Error('ModelProviderRegistry error: No configured model providers available.');
    }

    return configured[0];
  }
}
