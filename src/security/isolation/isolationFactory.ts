import {
  IIsolationProvider,
  IIsolationEnvironment
} from './isolationProvider.interface.js';
import {
  IsolationLevel,
  IsolationPolicy,
  meetsIsolationRequirement
} from './isolationTypes.js';
import { CapabilityGrant } from '../../core/types.js';
import { ContainerIsolationProvider } from './containerProvider.js';
import { ProcessIsolationProvider } from './processProvider.js';
import { HostFallbackProvider } from './hostFallbackProvider.js';

export class IsolationFactory {
  private readonly providers: IIsolationProvider[] = [];

  constructor(customProviders?: IIsolationProvider[]) {
    if (customProviders && customProviders.length > 0) {
      this.providers.push(...customProviders);
    } else {
      // Default order: strongest guaranteed provider first
      this.providers.push(
        new ContainerIsolationProvider(),
        new ProcessIsolationProvider(),
        new HostFallbackProvider()
      );
    }
  }

  registerProvider(provider: IIsolationProvider): void {
    this.providers.unshift(provider);
  }

  getRegisteredProviders(): readonly IIsolationProvider[] {
    return this.providers;
  }

  /**
   * Selects the strongest available provider that strictly satisfies policy.requiredLevel.
   * Compares the actual guaranteed isolation strength (not just the provider name).
   *
   * If policy.requiredLevel = CONTAINER and ContainerIsolationProvider is unavailable:
   * Returns NULL (fails closed). It will NEVER return HostFallbackProvider or ProcessIsolationProvider!
   */
  async selectProvider(policy: IsolationPolicy): Promise<IIsolationProvider | null> {
    const requiredLevel = policy.requiredLevel;

    for (const provider of this.providers) {
      // 1. Check if provider's guaranteed level satisfies required level
      const satisfiesStrength = meetsIsolationRequirement(provider.isolationLevel, requiredLevel);
      if (!satisfiesStrength) {
        continue;
      }

      // 2. Check if provider is available on current host
      try {
        const available = await provider.isAvailable();
        if (available) {
          return provider;
        }
      } catch {
        // Provider check threw error, skip
        continue;
      }
    }

    // No registered available provider could satisfy the required isolation level
    return null;
  }

  /**
   * Creates an isolation environment satisfying the required isolation policy.
   * Fails closed if no provider can satisfy the policy.
   */
  async createEnvironment(
    policy: IsolationPolicy,
    capability: CapabilityGrant
  ): Promise<IIsolationEnvironment> {
    const provider = await this.selectProvider(policy);
    if (!provider) {
      throw new Error(
        `ISOLATION_UNSATISFIABLE: Required isolation level "${policy.requiredLevel}" cannot be satisfied by any available isolation provider on this host.`
      );
    }

    return provider.createEnvironment(policy, capability);
  }
}
