export const template_group_types = [
  // {
  //   id: 'response-anomalies',
  //   label: 'Response Anomalies',
  //   description: 'Templates that monitor error-prone HTTP response patterns.'
  // },
  {
    id: 'performance-monitoring',
    label: 'Performance Monitoring',
    description: 'Templates that highlight latency or throughput concerns.'
  },
  {
    id: 'mcp-visibility',
    label: 'MCP Visibility',
    description: 'Templates that surface Model Context Protocol traffic patterns.'
  },
  {
    id: 'slo-guardrails',
    label: 'SLO & Performance Guardrails',
    description: 'Templates that watch SLO-protected traffic for breaches.'
  },
  {
    id: 'webhooks',
    label: 'Webhooks',
    description:
      'Templates that normalize event metadata, signatures, retries, and provider specifics.'
  },
  {
    id: 'release-feature',
    label: 'Tenant & Feature Flags',
    description: 'Templates that add business context like branch, build, tenant, version, and feature toggles.'
  },
  {
    id: 'rate-limiting',
    label: 'Rate Limiting & Quotas',
    description: 'Templates that standardize and surface rate-limit signals.'
  },
  {
    id: 'security-auth',
    label: 'Security & Auth',
    description: 'Templates that surface authentication/authorization context and failures.'
  },
  // {
  //   id: 'security-oauth',
  //   label: 'OAuth',
  //   description:
  //     'Templates that surface OAuth/OIDC grant flows, client identity, errors, and token characteristics.'
  // },
  // {
  //   id: 'release-infra',
  //   label: 'Release & Infra Context',
  //   description: 'Templates that attach branch/build/region/owner for faster incident triage.'
  // },
  {
    id: 'payload-tagging',
    label: 'Payload',
    description: 'Templates that lift safe, stable identifiers from payloads.'
  }
];

const templates = [
  // {
  //   id: 'tmpl-response-5xx',
  //   name: 'Tag 5xx responses',
  //   description: 'Adds error tags when the upstream responds with a 5xx status code.',
  //   event: 'inspectr.operation.completed',
  //   priority: 100,
  //   group_type: 'response-anomalies',
  //   expression: {
  //     op: 'range',
  //     left: {
  //       path: '$.response.status'
  //     },
  //     right: [500, 599]
  //   },
  //   actions: [
  //     {
  //       type: 'inspectr.tag.static',
  //       params: {
  //         tags: ['error', 'server-error']
  //       }
  //     }
  //   ]
  // },
  // {
  //   id: 'tmpl-auth-4xx',
  //   name: 'Surface auth failures',
  //   description:
  //     'Detects authentication endpoints returning a 4xx response and tags them for follow-up.',
  //   event: 'inspectr.operation.completed',
  //   priority: 80,
  //   group_type: 'response-anomalies',
  //   expression: {
  //     op: 'and',
  //     args: [
  //       {
  //         op: 'range',
  //         left: {
  //           path: '$.response.status'
  //         },
  //         right: [400, 499]
  //       },
  //       {
  //         op: 'matches',
  //         left: {
  //           path: '$.request.path'
  //         },
  //         right: '(?i)(login|signin|auth)'
  //       }
  //     ]
  //   },
  //   actions: [
  //     {
  //       type: 'inspectr.tag.static',
  //       params: {
  //         tags: ['auth', 'client-error']
  //       }
  //     }
  //   ]
  // },
  {
    id: 'tmpl-mcp-generic',
    name: 'Tag MCP traffic',
    description: 'Adds a generic MCP tag to requests routed through the MCP gateway.',
    event: 'inspectr.operation.completed',
    priority: 70,
    group_type: 'mcp-visibility',
    expression: {
      op: '==',
      left: {
        path: '$.request.path'
      },
      right: '/mcp'
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: {
          tags: ['mcp']
        }
      }
    ]
  },
  {
    id: 'tmpl-mcp-tools',
    name: 'Tag MCP tool calls',
    description: 'Labels MCP tool invocations and tags them with the requested tool name.',
    event: 'inspectr.operation.completed',
    priority: 60,
    group_type: 'mcp-visibility',
    expression: {
      op: 'and',
      args: [
        {
          op: '==',
          left: {
            path: '$.request.path'
          },
          right: '/mcp'
        },
        {
          op: 'contains',
          left: {
            path: '$.request.body'
          },
          right: '"method":"tools/call"'
        }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: {
          tags: ['mcp', 'mcp.tools']
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'params.name',
          prefix: 'mcp.tool.'
        }
      }
    ]
  },
  {
    id: 'tmpl-mcp-resources',
    name: 'Tag MCP resource access',
    description:
      'Highlights MCP resource interactions and tags them with the requested resource identifier.',
    event: 'inspectr.operation.completed',
    priority: 55,
    group_type: 'mcp-visibility',
    expression: {
      op: 'and',
      args: [
        {
          op: '==',
          left: {
            path: '$.request.path'
          },
          right: '/mcp'
        },
        {
          op: 'contains',
          left: {
            path: '$.request.body'
          },
          right: '"method":"resources/'
        }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: {
          tags: ['mcp', 'mcp.resources']
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'params.uri',
          prefix: 'mcp.resource.'
        }
      }
    ]
  },
  {
    id: 'tmpl-mcp-prompts',
    name: 'Tag MCP prompt usage',
    description: 'Tags MCP prompt calls and enriches them with the prompt name used.',
    event: 'inspectr.operation.completed',
    priority: 50,
    group_type: 'mcp-visibility',
    expression: {
      op: 'and',
      args: [
        {
          op: '==',
          left: {
            path: '$.request.path'
          },
          right: '/mcp'
        },
        {
          op: 'contains',
          left: {
            path: '$.request.body'
          },
          right: '"method":"prompts/call"'
        }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: {
          tags: ['mcp', 'mcp.prompts']
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'params.name',
          prefix: 'mcp.prompt.'
        }
      }
    ]
  },
  {
    id: 'tmpl-slo-latency-warning',
    name: 'SLO latency warning',
    description: 'Flags SLO-protected API calls whose latency is trending high (500-999 ms).',
    event: 'inspectr.operation.completed',
    priority: 40,
    group_type: 'slo-guardrails',
    expression: {
      op: 'and',
      args: [
        {
          op: 'matches',
          left: {
            path: '$.request.path'
          },
          right: '(?i)^/api/'
        },
        {
          op: 'range',
          left: {
            path: '$.timing.duration'
          },
          right: [500, 999]
        }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: {
          tags: ['slo', 'slo.latency', 'slo.warning']
        }
      }
    ]
  },
  {
    id: 'tmpl-slo-latency-breach',
    name: 'SLO latency breach',
    description: 'Captures SLO-protected API calls breaching the 1s latency objective.',
    event: 'inspectr.operation.completed',
    priority: 35,
    group_type: 'slo-guardrails',
    expression: {
      op: 'and',
      args: [
        {
          op: 'matches',
          left: {
            path: '$.request.path'
          },
          right: '(?i)^/api/'
        },
        {
          op: '>=',
          left: {
            path: '$.timing.duration'
          },
          right: 1000
        }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: {
          tags: ['slo', 'slo.latency', 'slo.breach']
        }
      }
    ]
  },
  {
    id: 'tmpl-slo-response-slow',
    name: 'Slow responses (+1 second)',
    description: 'Highlights operations whose total duration is one second or longer.',
    event: 'inspectr.operation.completed',
    priority: 90,
    group_type: 'slo-guardrails',
    expression: {
      op: '>=',
      left: {
        path: '$.timing.duration'
      },
      right: 1000
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: {
          tags: ['slow']
        }
      }
    ]
  },
  {
    id: 'tmpl-slo-error-budget',
    name: 'SLO error budget hit',
    description: 'Highlights 5xx responses on SLO-protected APIs as error budget burns.',
    event: 'inspectr.operation.completed',
    priority: 30,
    group_type: 'slo-guardrails',
    expression: {
      op: 'and',
      args: [
        {
          op: 'matches',
          left: {
            path: '$.request.path'
          },
          right: '(?i)^/api/'
        },
        {
          op: 'range',
          left: {
            path: '$.response.status'
          },
          right: [500, 599]
        }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: {
          tags: ['slo', 'slo.error', 'slo.error-budget']
        }
      }
    ]
  },
  {
    id: 'tmpl-cloudevents-normalize',
    name: 'Tag CloudEvents metadata',
    description: 'Tags CloudEvents requests with ce.type, ce.id, ce.source (from headers or body).',
    event: 'inspectr.operation.completed',
    priority: 110,
    group_type: 'webhooks',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.request.headers.ce-type' }, right: '.+' },
        { op: 'matches', left: { path: '$.request.body.specversion' }, right: '.+' }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['cloudevents'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.ce-type', key: 'ce.type', fallback: 'unknown' }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.ce-id', key: 'ce.id', fallback: 'unknown' }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.headers.ce-source',
          key: 'ce.source',
          fallback: 'unknown'
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'type',
          key: 'ce.type',
          fallback: 'unknown'
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'id',
          key: 'ce.id',
          fallback: 'unknown'
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'source',
          key: 'ce.source',
          fallback: 'unknown'
        }
      }
    ]
  },
  {
    id: 'tmpl-webhook-stripe',
    name: 'Stripe webhook tagging',
    description: 'Tags Stripe webhooks with event type and signature presence.',
    event: 'inspectr.operation.completed',
    priority: 108,
    group_type: 'webhooks',
    expression: {
      op: 'matches',
      left: { path: '$.request.headers.stripe-signature' },
      right: '.+'
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: { tags: ['webhook', 'provider.stripe', 'sig.present'] }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'type',
          key: 'stripe.event',
          fallback: 'unknown'
        }
      }
    ]
  },
  {
    id: 'tmpl-webhook-github',
    name: 'GitHub webhook tagging',
    description: 'Tags GitHub webhooks with delivery id and signature presence.',
    event: 'inspectr.operation.completed',
    priority: 107,
    group_type: 'webhooks',
    expression: {
      op: 'matches',
      left: { path: '$.request.headers.x-github-delivery' },
      right: '.+'
    },
    actions: [
      {
        type: 'inspectr.tag.static',
        params: { tags: ['webhook', 'provider.github', 'sig.sha256'] }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.x-github-delivery', key: 'github.delivery' }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.headers.x-github-event',
          key: 'github.event',
          fallback: 'unknown'
        }
      }
    ]
  },
  {
    id: 'tmpl-webhook-retry',
    name: 'Webhook retry detection',
    description: 'Labels webhook deliveries carrying a retry/attempt counter.',
    event: 'inspectr.operation.completed',
    priority: 102,
    group_type: 'webhooks',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.request.headers.x-retry-count' }, right: '^[0-9]+$' },
        { op: 'matches', left: { path: '$.request.body.attempt' }, right: '^[0-9]+$' }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['webhook', 'webhook.retry'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.x-retry-count', key: 'retry.count', fallback: '' }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'attempt',
          key: 'retry.count',
          fallback: ''
        }
      }
    ]
  },
  {
    id: 'tmpl-webhook-generic-event',
    name: 'Generic webhook event type',
    description:
      "Tags webhook event types for non-CloudEvents bodies using 'event' or 'type' fields.",
    event: 'inspectr.operation.completed',
    priority: 97,
    group_type: 'webhooks',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.request.body.event' }, right: '.+' },
        { op: 'matches', left: { path: '$.request.body.type' }, right: '.+' }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['webhook'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'event',
          key: 'event.type',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'type',
          key: 'event.type',
          fallback: ''
        }
      }
    ]
  },
  {
    id: 'tmpl-idempotency-key',
    name: 'Idempotency-Key capture',
    description: 'Tags requests using Idempotency-Key for duplicate/retry analysis.',
    event: 'inspectr.operation.completed',
    priority: 106,
    group_type: 'release-feature',
    expression: {
      op: 'matches',
      left: { path: '$.request.headers.idempotency-key' },
      right: '.+'
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['idempotent'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.idempotency-key', key: 'idempotency' }
      }
    ]
  },
  {
    id: 'tmpl-ratelimit-present',
    name: 'Tag RateLimit headers',
    description: 'Tags responses that include standard or legacy rate limit headers.',
    event: 'inspectr.operation.completed',
    priority: 105,
    group_type: 'rate-limiting',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.response.headers.ratelimit' }, right: '.+' },
        { op: 'matches', left: { path: '$.response.headers.ratelimit-policy' }, right: '.+' },
        { op: 'matches', left: { path: '$.response.headers.x-ratelimit-remaining' }, right: '.+' }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['ratelimit'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.response.headers.x-ratelimit-remaining',
          key: 'ratelimit.remaining',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.response.headers.ratelimit-remaining',
          key: 'ratelimit.remaining',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.response.headers.ratelimit-policy',
          key: 'ratelimit.policy',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.response.headers.ratelimit-reset',
          key: 'ratelimit.reset',
          fallback: ''
        }
      }
    ]
  },
  {
    id: 'tmpl-ratelimit-low',
    name: 'RateLimit nearly exhausted',
    description: 'Labels responses where remaining quota is critically low (<= 5).',
    event: 'inspectr.operation.completed',
    priority: 104,
    group_type: 'rate-limiting',
    expression: {
      op: 'and',
      args: [
        {
          op: 'matches',
          left: { path: '$.response.headers.ratelimit-remaining' },
          right: '^[0-9]+$'
        },
        { op: '<=', left: { path: '$.response.headers.ratelimit-remaining' }, right: 5 }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['ratelimit', 'ratelimit.low'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.response.headers.ratelimit-reset',
          key: 'ratelimit.reset',
          fallback: ''
        }
      }
    ]
  },
  {
    id: 'tmpl-ratelimit-429-retry-after',
    name: 'Throttled with Retry-After',
    description: 'Tags responses that were throttled and include Retry-After guidance.',
    event: 'inspectr.operation.completed',
    priority: 94,
    group_type: 'rate-limiting',
    expression: {
      op: 'and',
      args: [
        { op: '==', left: { path: '$.response.status' }, right: 429 },
        { op: 'matches', left: { path: '$.response.headers.retry-after' }, right: '.+' }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['throttled'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.response.headers.retry-after', key: 'retry.after', fallback: '' }
      }
    ]
  },
  {
    id: 'tmpl-auth-401-403-any',
    name: 'Auth failures (401/403)',
    description: 'Tags authentication/authorization failures regardless of endpoint path.',
    event: 'inspectr.operation.completed',
    priority: 103,
    group_type: 'security-auth',
    expression: {
      op: 'or',
      args: [
        { op: '==', left: { path: '$.response.status' }, right: 401 },
        { op: '==', left: { path: '$.response.status' }, right: 403 }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['auth', 'access-denied'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.headers.authorization',
          key: 'auth.scheme',
          fallback: 'none'
        }
      }
    ]
  },
  {
    id: 'tmpl-api-version-detect',
    name: 'API version detection',
    description: 'Tags the API version from the URL path (/api/vN/...) or X-API-Version header.',
    event: 'inspectr.operation.completed',
    priority: 101,
    group_type: 'release-feature',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.request.path' }, right: '^/api/v([0-9]+)(/|$)' },
        { op: 'matches', left: { path: '$.request.headers.x-api-version' }, right: '.+' }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.path', key: 'api.version', fallback: '' }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.x-api-version', key: 'api.version', fallback: '' }
      }
    ]
  },
  {
    id: 'tmpl-tenant-detect',
    name: 'Tenant / customer tagging',
    description: 'Tags tenant/customer from X-Customer-Id header or request body tenantId.',
    event: 'inspectr.operation.completed',
    priority: 100,
    group_type: 'release-feature',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.request.headers.x-customer-id' }, right: '.+' },
        { op: 'matches', left: { path: '$.request.body.tenantId' }, right: '.+' }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.x-customer-id', key: 'tenant', fallback: '' }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'tenantId',
          key: 'tenant',
          fallback: ''
        }
      }
    ]
  },
  {
    id: 'tmpl-feature-flag-detect',
    name: 'Feature flag / experiment tagging',
    description: 'Tags feature flag or experiment id from headers (X-Feature-Flag / X-Experiment).',
    event: 'inspectr.operation.completed',
    priority: 99,
    group_type: 'release-feature',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.request.headers.x-feature-flag' }, right: '.+' },
        { op: 'matches', left: { path: '$.request.headers.x-experiment' }, right: '.+' }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.x-feature-flag', key: 'feature', fallback: '' }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.x-experiment', key: 'experiment', fallback: '' }
      }
    ]
  },
  {
    id: 'tmpl-primary-id-lift',
    name: 'Primary identifier lift',
    description: 'Extracts stable identifiers (orderId, userId) from bodies for easy lookup.',
    event: 'inspectr.operation.completed',
    priority: 98,
    group_type: 'payload-tagging',
    expression: {
      op: 'or',
      args: [
        { op: 'contains', left: { path: '$.request.body' }, right: '"orderId"' },
        { op: 'contains', left: { path: '$.request.body' }, right: '"userId"' },
        { op: 'contains', left: { path: '$.response.body' }, right: '"orderId"' },
        { op: 'contains', left: { path: '$.response.body' }, right: '"userId"' }
      ]
    },
    actions: [
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'orderId',
          key: 'entity.order',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'userId',
          key: 'entity.user',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.response.body',
          json_path: 'orderId',
          key: 'entity.order',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.response.body',
          json_path: 'userId',
          key: 'entity.user',
          fallback: ''
        }
      }
    ]
  },
  {
    id: 'tmpl-trace-page-next-token',
    name: 'Trace pagination token (response)',
    description: 'Assigns trace using next page token in the response body to stitch paginated flows.',
    event: 'inspectr.operation.completed',
    priority: 87,
    group_type: 'payload-tagging',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.response.body.next_token' }, right: '.+' },
        { op: 'matches', left: { path: '$.response.body.nextPageToken' }, right: '.+' }
      ]
    },
    actions: [
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.response.body',
          json_path: 'next_token',
          prefix: 'page:',
          override_existing: false,
          max_length: 128
        }
      },
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.response.body',
          json_path: 'nextPageToken',
          prefix: 'page:',
          override_existing: false,
          max_length: 128
        }
      }
    ]
  },
  {
    id: 'tmpl-trace-page-token-request',
    name: 'Trace pagination token (request)',
    description: 'Assigns trace using page token in the request query to align pagination fetches.',
    event: 'inspectr.operation.completed',
    priority: 86,
    group_type: 'payload-tagging',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.request.query.page_token' }, right: '.+' },
        { op: 'matches', left: { path: '$.request.query.pageToken' }, right: '.+' }
      ]
    },
    actions: [
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.request.query.page_token',
          prefix: 'page:',
          override_existing: false,
          max_length: 128
        }
      },
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.request.query.pageToken',
          prefix: 'page:',
          override_existing: false,
          max_length: 128
        }
      }
    ]
  },
  {
    id: 'tmpl-trace-location-header',
    name: 'Trace Location header (201 Created)',
    description: 'Assigns trace using the Location header for created resources to correlate follow-up operations.',
    event: 'inspectr.operation.completed',
    priority: 85,
    group_type: 'payload-tagging',
    expression: {
      op: 'and',
      args: [
        { op: '==', left: { path: '$.response.status' }, right: 201 },
        { op: 'matches', left: { path: '$.response.headers.location' }, right: '.+' }
      ]
    },
    actions: [
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.response.headers.location',
          prefix: 'loc:',
          override_existing: false,
          max_length: 256
        }
      }
    ]
  },
  {
    id: 'tmpl-trace-job-id-body',
    name: 'Trace Bulk / batch job id (body)',
    description: 'Assigns trace using job identifiers returned in the response body to stitch async flows.',
    event: 'inspectr.operation.completed',
    priority: 84,
    group_type: 'payload-tagging',
    expression: {
      op: 'or',
      args: [
        { op: 'matches', left: { path: '$.response.body.job_id' }, right: '.+' },
        { op: 'matches', left: { path: '$.response.body.jobId' }, right: '.+' }
      ]
    },
    actions: [
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.response.body',
          json_path: 'job_id',
          prefix: 'job:',
          override_existing: false,
          max_length: 128
        }
      },
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.response.body',
          json_path: 'jobId',
          prefix: 'job:',
          override_existing: false,
          max_length: 128
        }
      }
    ]
  },
  {
    id: 'tmpl-trace-job-id-header',
    name: 'Trace Bulk / batch job id (header)',
    description: 'Assigns trace using job identifiers returned in headers to stitch async flows.',
    event: 'inspectr.operation.completed',
    priority: 83,
    group_type: 'payload-tagging',
    expression: {
      op: 'matches',
      left: { path: '$.response.headers.x-job-id' },
      right: '.+'
    },
    actions: [
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.response.headers.x-job-id',
          prefix: 'job:',
          override_existing: false,
          max_length: 128
        }
      }
    ]
  },
  {
    id: 'tmpl-trace-session-header',
    name: 'Trace session (header)',
    description: 'Assigns trace using client-supplied X-Session-Id header to correlate user sessions.',
    event: 'inspectr.operation.completed',
    priority: 82,
    group_type: 'payload-tagging',
    expression: {
      op: 'matches',
      left: { path: '$.request.headers.x-session-id' },
      right: '.+'
    },
    actions: [
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.request.headers.x-session-id',
          prefix: 'sess:',
          override_existing: false,
          max_length: 128
        }
      }
    ]
  },
  // {
  //   id: 'tmpl-trace-session-cookie',
  //   name: 'Trace from session cookie (best-effort)',
  //   description: 'Assigns trace from Cookie header when it contains a session key; truncated to avoid leaking full cookie.',
  //   event: 'inspectr.operation.completed',
  //   priority: 81,
  //   group_type: 'payload-tagging',
  //   expression: {
  //     op: 'contains',
  //     left: { path: '$.request.headers.cookie' },
  //     right: 'session='
  //   },
  //   actions: [
  //     {
  //       type: 'inspectr.trace.assign',
  //       params: {
  //         source_path: '$.request.headers.cookie',
  //         prefix: 'sess:',
  //         override_existing: false,
  //         max_length: 80
  //       }
  //     }
  //   ]
  // },
  {
    id: 'tmpl-deployment-branch-build',
    name: 'Deployment branch & build tags',
    description: 'Adds git branch and build number tags for easy correlation with releases.',
    event: 'inspectr.operation.completed',
    priority: 95,
    group_type: 'release-feature',
    expression: { op: '==', left: { path: '$.meta.always' }, right: true },
    actions: [
      { type: 'inspectr.tag.git', params: { repo_path: '', key: 'git.branch', lowercase: true } },
      {
        type: 'inspectr.tag.file',
        params: {
          path: './build.json',
          json_path: 'buildNumber',
          key: 'build.number',
          fallback: 'unknown',
          lowercase: false
        }
      }
    ]
  },
  {
    id: 'tmpl-auth-4xx-login-endpoints',
    name: 'Surface auth failures (login paths)',
    description:
      'Detects 4xx on login/auth endpoints and tags for follow-up (complements generic 401/403).',
    event: 'inspectr.operation.completed',
    priority: 93,
    group_type: 'security-auth',
    expression: {
      op: 'and',
      args: [
        { op: 'range', left: { path: '$.response.status' }, right: [400, 499] },
        { op: 'matches', left: { path: '$.request.path' }, right: '(?i)(login|signin|auth)' }
      ]
    },
    actions: [{ type: 'inspectr.tag.static', params: { tags: ['auth', 'client-error'] } }]
  },
  {
    id: 'tmpl-oauth-grant-type',
    name: 'OAuth grant type tagging',
    description: 'Tags the OAuth grant type when calling token endpoints.',
    event: 'inspectr.operation.completed',
    priority: 92,
    group_type: 'security-auth',
    expression: {
      op: 'and',
      args: [
        {
          op: 'matches',
          left: { path: '$.request.path' },
          right: '(?i)(/oauth/token|/connect/token)'
        },
        {
          op: 'matches',
          left: { path: '$.request.body.grant_type' },
          right: '.+'
        }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['oauth'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'grant_type',
          key: 'oauth.grant',
          fallback: 'unknown'
        }
      }
    ]
  },
  {
    id: 'tmpl-oauth-error-codes',
    name: 'OAuth error code tagging',
    description: 'Tags OAuth/OIDC error codes returned by token/authorize endpoints.',
    event: 'inspectr.operation.completed',
    priority: 91,
    group_type: 'security-auth',
    expression: {
      op: 'and',
      args: [
        {
          op: 'matches',
          left: { path: '$.request.path' },
          right: '(?i)(/oauth/(token|authorize)|/connect/(token|authorize))'
        },
        {
          op: 'matches',
          left: { path: '$.response.body.error' },
          right: '(?i)(invalid_client|invalid_grant|invalid_scope|unauthorized_client)'
        }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['oauth', 'oauth.error'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.response.body',
          json_path: 'error',
          key: 'oauth.err',
          fallback: 'unknown'
        }
      }
    ]
  },
  {
    id: 'tmpl-oauth-client-id',
    name: 'OAuth client identity',
    description:
      'Tags the requesting OAuth client_id (from body or headers) for accountability and analysis.',
    event: 'inspectr.operation.completed',
    priority: 90,
    group_type: 'security-auth',
    expression: {
      op: 'and',
      args: [
        {
          op: 'matches',
          left: { path: '$.request.path' },
          right: '(?i)(/oauth/(token|authorize)|/connect/(token|authorize))'
        },
        {
          op: 'or',
          args: [
            { op: 'matches', left: { path: '$.request.body.client_id' }, right: '.+' },
            { op: 'matches', left: { path: '$.request.headers.x-client-id' }, right: '.+' },
            { op: 'matches', left: { path: '$.request.headers.client_id' }, right: '.+' }
          ]
        }
      ]
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['oauth'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'client_id',
          key: 'oauth.client_id',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.headers.x-client-id',
          key: 'oauth.client_id',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.request.headers.client_id', key: 'oauth.client_id', fallback: '' }
      }
    ]
  },
  {
    id: 'tmpl-oauth-token-type-aud',
    name: 'OAuth token type & audience',
    description:
      'Tags token_type from token responses and audience from request/response if present.',
    event: 'inspectr.operation.completed',
    priority: 89,
    group_type: 'security-auth',
    expression: {
      op: 'matches',
      left: { path: '$.request.path' },
      right: '(?i)(/oauth/token|/connect/token)'
    },
    actions: [
      { type: 'inspectr.tag.static', params: { tags: ['oauth'] } },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.response.body',
          json_path: 'token_type',
          key: 'oauth.token_type',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: {
          source_path: '$.request.body',
          json_path: 'audience',
          key: 'oauth.aud',
          fallback: ''
        }
      },
      {
        type: 'inspectr.tag.dynamic',
        params: { source_path: '$.response.body', json_path: 'aud', key: 'oauth.aud', fallback: '' }
      }
    ]
  },
  {
    id: 'tmpl-oauth-trace-steps',
    name: 'OAuth flow trace linkage',
    description:
      'Ensures trace assignment is captured for /authorize and /token steps to link the full OAuth flow.',
    event: 'inspectr.operation.completed',
    priority: 88,
    group_type: 'security-auth',
    expression: {
      op: 'matches',
      left: { path: '$.request.path' },
      right: '(?i)(/oauth/(authorize|token)|/connect/(authorize|token))'
    },
    actions: [
      {
        type: 'inspectr.trace.assign',
        params: {
          source_path: '$.request.headers.traceparent',
          prefix: '',
          lowercase: false,
          override_existing: false,
          fallback: ''
        }
      },
      { type: 'inspectr.tag.static', params: { tags: ['oauth', 'oauth.flow'] } }
    ]
  }
];
export default templates;
