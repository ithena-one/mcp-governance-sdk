import { createGovernedServer } from '../src/index.js';
import {
    InMemoryRoleStore,
    InMemoryPermissionStore,
    ConsoleLogger,
    ConsoleAuditLogStore,
    StrictIdentityResolver,
} from '../src/defaults/index.js';
import type { UserIdentity } from '../src/interfaces.js';

// Define some example roles and their permissions
const ROLES = {
    ADMIN: 'admin',
    EDITOR: 'editor',
    VIEWER: 'viewer',
};

const PERMISSIONS = {
    READ_DOCS: 'docs:read',
    WRITE_DOCS: 'docs:write',
    DELETE_DOCS: 'docs:delete',
    MANAGE_USERS: 'users:manage',
};

// Example document storage
const documents = new Map<string, { title: string; content: string }>();

async function main() {
    // Create stores for roles and permissions
    const roleStore = new InMemoryRoleStore();
    const permissionStore = new InMemoryPermissionStore();

    // Set up roles and their permissions
    async function setupRbac() {
        // Admin role has all permissions
        await roleStore.addRole('admin-user', ROLES.ADMIN);
        await permissionStore.addPermission(ROLES.ADMIN, PERMISSIONS.READ_DOCS);
        await permissionStore.addPermission(ROLES.ADMIN, PERMISSIONS.WRITE_DOCS);
        await permissionStore.addPermission(ROLES.ADMIN, PERMISSIONS.DELETE_DOCS);
        await permissionStore.addPermission(ROLES.ADMIN, PERMISSIONS.MANAGE_USERS);

        // Editor role can read and write docs
        await roleStore.addRole('editor-user', ROLES.EDITOR);
        await permissionStore.addPermission(ROLES.EDITOR, PERMISSIONS.READ_DOCS);
        await permissionStore.addPermission(ROLES.EDITOR, PERMISSIONS.WRITE_DOCS);

        // Viewer role can only read docs
        await roleStore.addRole('viewer-user', ROLES.VIEWER);
        await permissionStore.addPermission(ROLES.VIEWER, PERMISSIONS.READ_DOCS);
    }

    // Create a governed server with RBAC enabled
    const server = createGovernedServer({
        // Use strict identity validation
        identityResolver: new StrictIdentityResolver(),

        // Use console-based implementations for logging and auditing
        logger: new ConsoleLogger(),
        auditLogStore: new ConsoleAuditLogStore(),

        // Use in-memory stores for roles and permissions
        roleStore,
        permissionStore,

        // Enable RBAC
        enableRbac: true,

        // Define permission requirements for each method
        derivePermission: (message) => {
            switch (message.method) {
                case 'docs.read':
                    return PERMISSIONS.READ_DOCS;
                case 'docs.write':
                    return PERMISSIONS.WRITE_DOCS;
                case 'docs.delete':
                    return PERMISSIONS.DELETE_DOCS;
                case 'users.manage':
                    return PERMISSIONS.MANAGE_USERS;
                default:
                    return null; // No permission required
            }
        },

        // Define handlers for document operations
        handlers: {
            // Read a document
            'docs.read': async (params: { id: string }, context) => {
                const doc = documents.get(params.id);
                if (!doc) {
                    throw new Error(`Document ${params.id} not found`);
                }
                context.logger.info('Reading document', { id: params.id });
                return doc;
            },

            // Write a document
            'docs.write': async (
                params: { id: string; title: string; content: string },
                context
            ) => {
                documents.set(params.id, {
                    title: params.title,
                    content: params.content,
                });
                context.logger.info('Writing document', { id: params.id });
                return { success: true };
            },

            // Delete a document
            'docs.delete': async (params: { id: string }, context) => {
                if (!documents.has(params.id)) {
                    throw new Error(`Document ${params.id} not found`);
                }
                documents.delete(params.id);
                context.logger.info('Deleting document', { id: params.id });
                return { success: true };
            },

            // Get user roles
            'users.roles': async (params: { userId: string }, context) => {
                // Only admins can view other users' roles
                if (
                    params.userId !== context.identity &&
                    !(await permissionStore.hasPermission(
                        ROLES.ADMIN,
                        PERMISSIONS.MANAGE_USERS,
                        context
                    ))
                ) {
                    throw new Error('Unauthorized to view other users roles');
                }

                const roles = await roleStore.getRoles(params.userId);
                return { roles };
            },
        },
    });

    // Initialize RBAC
    await setupRbac();

    // Test different operations with different user roles
    async function testOperations() {
        const adminUser: UserIdentity = 'admin-user';
        const editorUser: UserIdentity = 'editor-user';
        const viewerUser: UserIdentity = 'viewer-user';

        try {
            // Admin operations
            console.log('\nTesting admin operations...');
            await server.execute(adminUser, 'docs.write', {
                id: 'doc1',
                title: 'Test Document',
                content: 'This is a test document.',
            });
            console.log('Admin wrote document');

            const doc = await server.execute(adminUser, 'docs.read', { id: 'doc1' });
            console.log('Admin read document:', doc);

            const adminRoles = await server.execute(adminUser, 'users.roles', {
                userId: editorUser,
            });
            console.log('Admin viewed editor roles:', adminRoles);

            // Editor operations
            console.log('\nTesting editor operations...');
            await server.execute(editorUser, 'docs.read', { id: 'doc1' });
            console.log('Editor read document');

            await server.execute(editorUser, 'docs.write', {
                id: 'doc2',
                title: 'Editor Document',
                content: 'This is written by an editor.',
            });
            console.log('Editor wrote document');

            try {
                await server.execute(editorUser, 'docs.delete', { id: 'doc1' });
            } catch (error) {
                console.log('Editor failed to delete document (as expected)');
            }

            // Viewer operations
            console.log('\nTesting viewer operations...');
            await server.execute(viewerUser, 'docs.read', { id: 'doc1' });
            console.log('Viewer read document');

            try {
                await server.execute(viewerUser, 'docs.write', {
                    id: 'doc3',
                    title: 'Viewer Document',
                    content: 'This should fail.',
                });
            } catch (error) {
                console.log('Viewer failed to write document (as expected)');
            }
        } catch (error) {
            console.error('Error during test:', error);
        }
    }

    // Run the tests
    await testOperations();
}

// Run the example
main().catch(console.error); 