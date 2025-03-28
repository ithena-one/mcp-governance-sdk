/* eslint-disable @typescript-eslint/no-explicit-any */
// src/defaults/permissions.test.ts
import { defaultDerivePermission, InMemoryRoleStore, InMemoryPermissionStore } from '../defaults/permissions.js';
import { TransportContext, OperationContext } from '../types.js'; 

describe('Default Permissions Logic', () => {

    describe('defaultDerivePermission', () => {
        const mockTransportContext: TransportContext = { transportType: 'test' };
        const createMockRequest = (method: string, params?: any): Request => ({
            method,
            ...(params && { params }),
        });

        it('should return null for initialize and ping', () => {
            expect(defaultDerivePermission(createMockRequest('initialize'), mockTransportContext)).toBeNull();
            expect(defaultDerivePermission(createMockRequest('ping'), mockTransportContext)).toBeNull();
        });

        it('should derive tool permissions', () => {
            expect(defaultDerivePermission(createMockRequest('tools/call', { name: 'my_tool' }), mockTransportContext)).toBe('tool:call:my_tool');
            expect(defaultDerivePermission(createMockRequest('tools/call'), mockTransportContext)).toBe('tool:call'); // No name
            expect(defaultDerivePermission(createMockRequest('tools/list'), mockTransportContext)).toBe('tool:list');
        });

        it('should derive resource permissions', () => {
            expect(defaultDerivePermission(createMockRequest('resources/read', { uri: 'file:///data.txt' }), mockTransportContext)).toBe('resource:read:file:///data.txt');
            expect(defaultDerivePermission(createMockRequest('resources/read'), mockTransportContext)).toBe('resource:read'); // No URI
            expect(defaultDerivePermission(createMockRequest('resources/list'), mockTransportContext)).toBe('resource:list');
            expect(defaultDerivePermission(createMockRequest('resources/templates/list'), mockTransportContext)).toBe('resource:templates:list');
            expect(defaultDerivePermission(createMockRequest('resources/subscribe', { uri: 'db://table' }), mockTransportContext)).toBe('resource:subscribe:db://table');
            expect(defaultDerivePermission(createMockRequest('resources/subscribe'), mockTransportContext)).toBe('resource:subscribe:*'); // Default URI
            expect(defaultDerivePermission(createMockRequest('resources/unsubscribe', { uri: 'ws://feed' }), mockTransportContext)).toBe('resource:unsubscribe:ws://feed');
            expect(defaultDerivePermission(createMockRequest('resources/unsubscribe'), mockTransportContext)).toBe('resource:unsubscribe:*');
        });

         it('should derive prompt permissions', () => {
             expect(defaultDerivePermission(createMockRequest('prompts/get', { name: 'my_prompt' }), mockTransportContext)).toBe('prompt:get:my_prompt');
             expect(defaultDerivePermission(createMockRequest('prompts/get'), mockTransportContext)).toBe('prompt:get');
             expect(defaultDerivePermission(createMockRequest('prompts/list'), mockTransportContext)).toBe('prompt:list');
         });

        it('should derive completion permissions', () => {
            const promptRef = { type: 'ref/prompt', name: 'p1' };
            const resourceRef = { type: 'ref/resource', uri: 'uri1' };
            const arg = { name: 'arg1' };
            expect(defaultDerivePermission(createMockRequest('completion/complete', { ref: promptRef, argument: arg }), mockTransportContext)).toBe('completion:prompt:p1:arg1');
            expect(defaultDerivePermission(createMockRequest('completion/complete', { ref: promptRef }), mockTransportContext)).toBe('completion:prompt:p1:*'); // No arg name
            expect(defaultDerivePermission(createMockRequest('completion/complete', { ref: resourceRef, argument: arg }), mockTransportContext)).toBe('completion:resource:uri1:arg1');
            expect(defaultDerivePermission(createMockRequest('completion/complete', { ref: resourceRef }), mockTransportContext)).toBe('completion:resource:uri1:*');
            expect(defaultDerivePermission(createMockRequest('completion/complete'), mockTransportContext)).toBe('completion:complete'); // No ref
        });

         it('should derive other standard permissions', () => {
             expect(defaultDerivePermission(createMockRequest('sampling/createMessage'), mockTransportContext)).toBe('sampling:createMessage');
             expect(defaultDerivePermission(createMockRequest('roots/list'), mockTransportContext)).toBe('roots:list');
             expect(defaultDerivePermission(createMockRequest('logging/setLevel'), mockTransportContext)).toBe('logging:setLevel');
         });

        it('should return method name for unknown methods', () => {
            expect(defaultDerivePermission(createMockRequest('custom/action'), mockTransportContext)).toBe('custom/action');
        });
    });

    describe('InMemoryRoleStore', () => {
        const mockOpCtx = {} as OperationContext; // Mock context as needed
        let roleStore: InMemoryRoleStore;

        beforeEach(() => {
            roleStore = new InMemoryRoleStore({
                'user1': ['admin', 'dev'],
                'user2': ['viewer'],
            });
        });

        it('should get roles for known user (string ID)', async () => {
            const roles = await roleStore.getRoles('user1', mockOpCtx);
            expect(roles).toEqual(expect.arrayContaining(['admin', 'dev']));
            expect(roles.length).toBe(2);
        });

         it('should get roles for known user (object ID)', async () => {
             const roles = await roleStore.getRoles({ id: 'user2', email: '...' }, mockOpCtx);
             expect(roles).toEqual(['viewer']);
         });

        it('should return empty array for unknown user', async () => {
            expect(await roleStore.getRoles('unknown', mockOpCtx)).toEqual([]);
        });

         it('should return empty array for null identity', async () => {
             expect(await roleStore.getRoles(null as any, mockOpCtx)).toEqual([]);
         });

        it('should add roles to a user', async () => {
            roleStore.addUserRoles('user2', ['editor']);
            expect(await roleStore.getRoles('user2', mockOpCtx)).toEqual(expect.arrayContaining(['viewer', 'editor']));

            roleStore.addUserRoles('user3', ['tester']); // Add to new user
            expect(await roleStore.getRoles('user3', mockOpCtx)).toEqual(['tester']);
        });

        it('should remove roles from a user', async () => {
            roleStore.removeUserRoles('user1', ['dev', 'nonexistent']);
            expect(await roleStore.getRoles('user1', mockOpCtx)).toEqual(['admin']);

             roleStore.removeUserRoles('unknown', ['admin']); // Should not throw
             expect(await roleStore.getRoles('unknown', mockOpCtx)).toEqual([]);
        });
    });

    describe('InMemoryPermissionStore', () => {
         const mockOpCtx = {} as OperationContext; // Mock context as needed
         let permissionStore: InMemoryPermissionStore;

         beforeEach(() => {
             permissionStore = new InMemoryPermissionStore({
                 'admin': ['*'], // Admin can do anything
                 'dev': ['tool:call:dev_tool', 'resource:read:dev/*'],
                 'viewer': ['resource:read:public/*'],
             });
         });

         it('should grant permission for exact match', async () => {
             expect(await permissionStore.hasPermission('dev', 'tool:call:dev_tool', mockOpCtx)).toBe(true);
         });

         it('should deny permission for mismatch', async () => {
             expect(await permissionStore.hasPermission('dev', 'tool:call:admin_tool', mockOpCtx)).toBe(false);
         });

         it('should grant permission for wildcard role', async () => {
             expect(await permissionStore.hasPermission('admin', 'tool:call:admin_tool', mockOpCtx)).toBe(true);
             expect(await permissionStore.hasPermission('admin', 'resource:read:secret/file', mockOpCtx)).toBe(true);
             expect(await permissionStore.hasPermission('admin', 'any:other:permission', mockOpCtx)).toBe(true);
         });

          it('should return false for unknown role', async () => {
              expect(await permissionStore.hasPermission('unknown_role', 'tool:call:dev_tool', mockOpCtx)).toBe(false);
          });

          it('should return false for known role but unknown permission', async () => {
              expect(await permissionStore.hasPermission('viewer', 'resource:delete:public/file', mockOpCtx)).toBe(false);
          });


         it('should add permission to a role', async () => {
            expect(await permissionStore.hasPermission('viewer', 'tool:list', mockOpCtx)).toBe(false);
            permissionStore.addPermission('viewer', 'tool:list');
            expect(await permissionStore.hasPermission('viewer', 'tool:list', mockOpCtx)).toBe(true);

             permissionStore.addPermission('new_role', 'perm1'); // Add to new role
             expect(await permissionStore.hasPermission('new_role', 'perm1', mockOpCtx)).toBe(true);
         });

          it('should remove permission from a role', async () => {
              expect(await permissionStore.hasPermission('dev', 'tool:call:dev_tool', mockOpCtx)).toBe(true);
              permissionStore.removePermission('dev', 'tool:call:dev_tool');
              expect(await permissionStore.hasPermission('dev', 'tool:call:dev_tool', mockOpCtx)).toBe(false);

              permissionStore.removePermission('dev', 'nonexistent'); // Should not throw
              permissionStore.removePermission('unknown_role', 'perm1'); // Should not throw
          });
    });
});