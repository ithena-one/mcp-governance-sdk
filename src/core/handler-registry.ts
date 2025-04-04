import { z, ZodObject, ZodLiteral, ZodTypeAny } from 'zod';
import { GovernedRequestHandler, GovernedNotificationHandler } from './governed-server.js'; // Assuming types are exported from governed-server
import { Logger } from '../interfaces/logger.js';

// Re-define or import necessary types if not exported from governed-server
type AnyRequestSchema = ZodObject<{ method: ZodLiteral<string>;[key: string]: ZodTypeAny }>;
type AnyNotificationSchema = ZodObject<{ method: ZodLiteral<string>;[key: string]: ZodTypeAny }>;

export interface HandlerInfo<THandler, TSchema> {
    handler: THandler;
    schema: TSchema;
}

export class HandlerRegistry {
    private readonly requestHandlers: Map<string, HandlerInfo<GovernedRequestHandler<any>, AnyRequestSchema>> = new Map();
    private readonly notificationHandlers: Map<string, HandlerInfo<GovernedNotificationHandler<any>, AnyNotificationSchema>> = new Map();
    private isConnected = false;
    private readonly logger: Logger;

    constructor(logger: Logger) {
        this.logger = logger;
    }

    public setConnected(): void {
        this.isConnected = true;
    }

    public setDisconnected(): void {
        this.isConnected = false;
    }

    public registerRequestHandler<T extends AnyRequestSchema>(
        requestSchema: T,
        handler: GovernedRequestHandler<T>
    ): void {
        const method = requestSchema.shape.method.value;
        if (this.isConnected) {
            throw new Error(`Cannot register request handler for ${method} after connect() has been called.`);
        }
        if (this.requestHandlers.has(method)) {
            this.logger.warn(`Overwriting request handler for method: ${method}`);
        }
        this.requestHandlers.set(method, { handler: handler as any, schema: requestSchema });
        this.logger.debug(`Stored governed request handler for: ${method}`);
    }

    public registerNotificationHandler<T extends AnyNotificationSchema>(
        notificationSchema: T,
        handler: GovernedNotificationHandler<T>
    ): void {
        const method = notificationSchema.shape.method.value;
        if (this.isConnected) {
            throw new Error(`Cannot register notification handler for ${method} after connect() has been called.`);
        }
        if (this.notificationHandlers.has(method)) {
            this.logger.warn(`Overwriting notification handler for method: ${method}`);
        }
        this.notificationHandlers.set(method, { handler: handler as any, schema: notificationSchema });
        this.logger.debug(`Stored governed notification handler for: ${method}`);
    }

    public getRequestHandlers(): Map<string, HandlerInfo<GovernedRequestHandler<any>, AnyRequestSchema>> {
        return this.requestHandlers;
    }

    public getNotificationHandlers(): Map<string, HandlerInfo<GovernedNotificationHandler<any>, AnyNotificationSchema>> {
        return this.notificationHandlers;
    }

    public getRequestHandler(method: string): HandlerInfo<GovernedRequestHandler<any>, AnyRequestSchema> | undefined {
       return this.requestHandlers.get(method);
    }

    public getNotificationHandler(method: string): HandlerInfo<GovernedNotificationHandler<any>, AnyNotificationSchema> | undefined {
       return this.notificationHandlers.get(method);
    }
} 