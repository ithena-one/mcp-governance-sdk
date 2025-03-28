import { createGovernedServer } from '../src/index.js';
import {
    InMemoryRoleStore,
    InMemoryPermissionStore,
    ConsoleLogger,
    ConsoleAuditLogStore,
} from '../src/defaults/index.js';

async function main() {
    // Create stores for roles and permissions
    const roleStore = new InMemoryRoleStore();
    const permissionStore = new InMemoryPermissionStore();

    // Set up some initial roles and permissions
    const userId = 'user-123';
    await roleStore.addRole(userId, 'user');
    await permissionStore.addPermission(userId, 'read:docs');

    // Create a governed server with custom components
    const server = createGovernedServer({
        // Use console-based implementations for logging and auditing
        logger: new ConsoleLogger(),
        auditLogStore: new ConsoleAuditLogStore(),

        // Use in-memory stores for roles and permissions
        roleStore,
        permissionStore,

        // Define some example handlers
        handlers: {
            // Echo handler that returns its input
            'test.echo': async (params, context) => {
                context.logger.info('Executing echo', { params });
                return params;
            },

            // Handler that returns the current user's roles
            'user.roles': async (_, context) => {
                const roles = await roleStore.getRoles(context.identity);
                return { roles };
            },

            // Handler that returns the current user's permissions
            'user.permissions': async (_, context) => {
                const permissions = await permissionStore.getPermissions(context.identity);
                return { permissions };
            },
        },
    });

    try {
        // Test the echo handler
        const echoResult = await server.execute(userId, 'test.echo', {
            message: 'Hello, World!',
        });
        console.log('Echo result:', echoResult);

        // Test the roles handler
        const rolesResult = await server.execute(userId, 'user.roles', {});
        console.log('Roles result:', rolesResult);

        // Test the permissions handler
        const permissionsResult = await server.execute(userId, 'user.permissions', {});
        console.log('Permissions result:', permissionsResult);

        // Test error handling
        await server.execute(userId, 'nonexistent.method', {});
    } catch (error) {
        console.error('Error:', error);
    }
}

// Run the example
main().catch(console.error); 