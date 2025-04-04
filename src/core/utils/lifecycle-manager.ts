import { Logger } from '../../interfaces/logger.js';
import { IdentityResolver } from '../../interfaces/identity.js';
import { RoleStore, PermissionStore } from '../../interfaces/rbac.js';
import { CredentialResolver } from '../../interfaces/credentials.js';
import { AuditLogStore } from '../../interfaces/audit.js';

// Type alias for components with potential lifecycle methods
export type LifecycleComponent =
    | IdentityResolver
    | RoleStore
    | PermissionStore
    | CredentialResolver
    | AuditLogStore
    | Logger;

/**
 * Manages the initialization and shutdown lifecycle of governance components.
 */
export class LifecycleManager {
    private initializedComponents: LifecycleComponent[] = [];
    private readonly logger: Logger;
    private readonly components: LifecycleComponent[]; // Now we know this is non-null

    constructor(logger: Logger, components: Array<LifecycleComponent | undefined>) {
        this.logger = logger;
        // Filter out undefined components and those without lifecycle methods
        this.components = components.filter((c): c is LifecycleComponent => 
            c !== undefined && (('initialize' in c) || ('shutdown' in c))
        );
    }

    /**
     * Initializes all components that have an `initialize` method.
     * Throws the first error encountered during initialization.
     * @returns A list of successfully initialized components.
     */
    async initialize(): Promise<LifecycleComponent[]> {
        this.logger.debug("Initializing governance components...");
        this.initializedComponents = []; // Reset list

        for (const component of this.components) {
            // Skip undefined components
            if (!component) {
                continue;
            }

            if (component.initialize) {
                const componentName = ('name' in component) ? component.name : component.constructor?.name || 'Unnamed Component';
                try {
                    this.logger.debug(`Initializing ${componentName}...`);
                    await component.initialize();
                    this.initializedComponents.push(component); // Track success
                    this.logger.debug(`${componentName} initialized successfully.`);
                } catch (error) {
                    this.logger.error(`Failed to initialize ${componentName}`, error);
                    // Rethrow the error to halt the connect process
                    throw new Error(`Failed to initialize component ${componentName}: ${error instanceof Error ? error.message : String(error)}`);
                }
            }
        }
        this.logger.info("All applicable governance components initialized successfully.");
        return [...this.initializedComponents]; // Return a copy
    }

    /**
     * Shuts down all components that were successfully initialized and have a `shutdown` method.
     * Logs errors encountered during shutdown but does not throw.
     */
    async shutdown(): Promise<void> {
        if (this.initializedComponents.length === 0) {
            this.logger.debug("No initialized components to shut down.");
            return;
        }
        this.logger.debug(`Shutting down ${this.initializedComponents.length} governance components...`);

        const shutdownPromises = this.initializedComponents
            .filter(component => component.shutdown)
            .map(component => {
                const componentName = ('name' in component) ? component.name : component.constructor?.name || 'Unnamed Component';
                this.logger.debug(`Calling shutdown for ${componentName}...`);
                return Promise.resolve()
                    .then(() => component.shutdown!())
                    .then(() => ({ status: 'fulfilled' as const, componentName }))
                    .catch(err => ({ status: 'rejected' as const, reason: err, componentName }));
            });

        const results = await Promise.all(shutdownPromises);

        results.forEach(result => {
             if (result.status === 'rejected' && 'reason' in result) {
                 this.logger.error(`Error during ${result.componentName}.shutdown()`, { error: result.reason });
             } else if (result.status === 'fulfilled') {
                 this.logger.debug(`${result.componentName} shut down successfully.`);
             }
        });

        this.initializedComponents = []; // Clear the list
        this.logger.debug("Component shutdown process complete.");
    }

    /** Returns the list of components currently tracked as initialized. */
    getInitializedComponents(): LifecycleComponent[] {
        return [...this.initializedComponents];
    }
}