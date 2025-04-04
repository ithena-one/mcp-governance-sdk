import { metrics, ValueType, Attributes, Histogram, Counter } from '@opentelemetry/api';

// Use the same name as the tracer for consistency
const METER_NAME = '@ithena/mcp-governance';
// TODO: Ideally, find a way to inject the actual package version here
const METER_VERSION = '0.1.0';

// Get the meter instance (requires OTel SDK configured in the host app)
const meter = metrics.getMeter(METER_NAME, METER_VERSION);

// --- Define Metric Instruments ---

// Counts total requests/notifications processed by the governance pipeline
export const requestCounter: Counter<RequestMetricAttributes> = meter.createCounter('ithena.request.total',
    {
        description: 'Counts total requests/notifications processed by the Ithena governance pipeline.',
        valueType: ValueType.INT,
    }
);

// Measures the duration of the entire governance pipeline execution
export const requestDurationHistogram: Histogram<RequestMetricAttributes> = meter.createHistogram('ithena.request.duration.seconds',
    {
        description: 'Measures the duration of the entire Ithena governance pipeline execution.',
        unit: 's', // seconds
        valueType: ValueType.DOUBLE,
        // TODO: Consider adding explicit bucket boundaries for better Prometheus/Grafana compatibility later
        // adviceForConsumers: { explicitBucketBoundaries: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10] }
    }
);

// Measures the duration of individual pipeline steps (Identity, RBAC, etc.)
export const pipelineStepDurationHistogram: Histogram<StepMetricAttributes> = meter.createHistogram('ithena.pipeline.step.duration.seconds',
    {
        description: 'Measures the duration of individual Ithena governance pipeline steps.',
        unit: 's',
        valueType: ValueType.DOUBLE,
        // TODO: Consider explicit bucket boundaries here too
    }
);

// Counts attempts to log audit records and their outcome
export const auditLogCounter: Counter<AuditMetricAttributes> = meter.createCounter('ithena.audit.log.total',
    {
        description: 'Counts attempts to log audit records and their outcome.',
        valueType: ValueType.INT,
    }
);

// --- Define Attribute Types for Clarity ---

// Common attribute type for request-level metrics
export interface RequestMetricAttributes extends Attributes {
    'mcp.method': string;
    'mcp.type': 'request' | 'notification';
    'outcome.status': 'success' | 'failure' | 'denied'; // Final status of the operation
}

// Common attribute type for audit log attempt metrics
export interface AuditMetricAttributes extends Attributes {
     'outcome.status': 'success' | 'failure'; // Status of the attempt to log the audit record itself
}

// Common attribute type for pipeline step duration metrics
export interface StepMetricAttributes extends Attributes {
     'ithena.step.name': string; // e.g., 'Identity Resolution', 'RBAC Check'
     // Could add 'outcome.status' here too if we want duration broken down by success/failure of the step
}