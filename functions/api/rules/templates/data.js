export const template_group_types = [
    {
        "id": "response-anomalies",
        "label": "Response Anomalies",
        "description": "Templates that monitor error-prone HTTP response patterns."
    },
    {
        "id": "performance-monitoring",
        "label": "Performance Monitoring",
        "description": "Templates that highlight latency or throughput concerns."
    },
    {
        "id": "mcp-visibility",
        "label": "MCP Visibility",
        "description": "Templates that surface Model Context Protocol traffic patterns."
    },
    {
        "id": "slo-guardrails",
        "label": "SLO Guardrails",
        "description": "Templates that watch SLO-protected traffic for breaches."
    }
];

const templates = [
    {
        "id": "tmpl-response-5xx",
        "name": "Tag 5xx responses",
        "description": "Adds error tags when the upstream responds with a 5xx status code.",
        "event": "operation.completed",
        "priority": 100,
        "group_type": "response-anomalies",
        "expression": {
            "op": "range",
            "left": {
                "path": "$.response.status"
            },
            "right": [
                500,
                599
            ]
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "error",
                        "server-error"
                    ]
                }
            }
        ]
    },
    {
        "id": "tmpl-response-slow",
        "name": "Highlight slow responses",
        "description": "Labels operations whose total duration is one second or longer.",
        "event": "operation.completed",
        "priority": 90,
        "group_type": "performance-monitoring",
        "expression": {
            "op": ">=",
            "left": {
                "path": "$.timing.duration"
            },
            "right": 1000
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "slow"
                    ]
                }
            }
        ]
    },
    {
        "id": "tmpl-auth-4xx",
        "name": "Surface auth failures",
        "description": "Detects authentication endpoints returning a 4xx response and tags them for follow-up.",
        "event": "operation.completed",
        "priority": 80,
        "group_type": "response-anomalies",
        "expression": {
            "op": "and",
            "args": [
                {
                    "op": "range",
                    "left": {
                        "path": "$.response.status"
                    },
                    "right": [
                        400,
                        499
                    ]
                },
                {
                    "op": "matches",
                    "left": {
                        "path": "$.request.path"
                    },
                    "right": "(?i)(login|signin|auth)"
                }
            ]
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "auth",
                        "client-error"
                    ]
                }
            }
        ]
    },
    {
        "id": "tmpl-mcp-generic",
        "name": "Tag MCP traffic",
        "description": "Adds a generic MCP tag to requests routed through the MCP gateway.",
        "event": "operation.completed",
        "priority": 70,
        "group_type": "mcp-visibility",
        "expression": {
            "op": "==",
            "left": {
                "path": "$.request.path"
            },
            "right": "/mcp"
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "mcp"
                    ]
                }
            }
        ]
    },
    {
        "id": "tmpl-mcp-tools",
        "name": "Tag MCP tool calls",
        "description": "Labels MCP tool invocations and tags them with the requested tool name.",
        "event": "operation.completed",
        "priority": 60,
        "group_type": "mcp-visibility",
        "expression": {
            "op": "and",
            "args": [
                {
                    "op": "==",
                    "left": {
                        "path": "$.request.path"
                    },
                    "right": "/mcp"
                },
                {
                    "op": "contains",
                    "left": {
                        "path": "$.request.body"
                    },
                    "right": "\"method\":\"tools/call\""
                }
            ]
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "mcp",
                        "mcp.tools"
                    ]
                }
            },
            {
                "type": "tag_dynamic",
                "params": {
                    "source_path": "$.request.body",
                    "json_path": "params.name",
                    "prefix": "mcp.tool."
                }
            }
        ]
    },
    {
        "id": "tmpl-mcp-resources",
        "name": "Tag MCP resource access",
        "description": "Highlights MCP resource interactions and tags them with the requested resource identifier.",
        "event": "operation.completed",
        "priority": 55,
        "group_type": "mcp-visibility",
        "expression": {
            "op": "and",
            "args": [
                {
                    "op": "==",
                    "left": {
                        "path": "$.request.path"
                    },
                    "right": "/mcp"
                },
                {
                    "op": "contains",
                    "left": {
                        "path": "$.request.body"
                    },
                    "right": "\"method\":\"resources/"
                }
            ]
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "mcp",
                        "mcp.resources"
                    ]
                }
            },
            {
                "type": "tag_dynamic",
                "params": {
                    "source_path": "$.request.body",
                    "json_path": "params.uri",
                    "prefix": "mcp.resource."
                }
            }
        ]
    },
    {
        "id": "tmpl-mcp-prompts",
        "name": "Tag MCP prompt usage",
        "description": "Tags MCP prompt calls and enriches them with the prompt name used.",
        "event": "operation.completed",
        "priority": 50,
        "group_type": "mcp-visibility",
        "expression": {
            "op": "and",
            "args": [
                {
                    "op": "==",
                    "left": {
                        "path": "$.request.path"
                    },
                    "right": "/mcp"
                },
                {
                    "op": "contains",
                    "left": {
                        "path": "$.request.body"
                    },
                    "right": "\"method\":\"prompts/call\""
                }
            ]
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "mcp",
                        "mcp.prompts"
                    ]
                }
            },
            {
                "type": "tag_dynamic",
                "params": {
                    "source_path": "$.request.body",
                    "json_path": "params.name",
                    "prefix": "mcp.prompt."
                }
            }
        ]
    },
    {
        "id": "tmpl-slo-latency-warning",
        "name": "SLO latency warning",
        "description": "Flags SLO-protected API calls whose latency is trending high (500-999 ms).",
        "event": "operation.completed",
        "priority": 40,
        "group_type": "slo-guardrails",
        "expression": {
            "op": "and",
            "args": [
                {
                    "op": "matches",
                    "left": {
                        "path": "$.request.path"
                    },
                    "right": "(?i)^/api/"
                },
                {
                    "op": "range",
                    "left": {
                        "path": "$.timing.duration"
                    },
                    "right": [
                        500,
                        999
                    ]
                }
            ]
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "slo",
                        "slo.latency",
                        "slo.warning"
                    ]
                }
            }
        ]
    },
    {
        "id": "tmpl-slo-latency-breach",
        "name": "SLO latency breach",
        "description": "Captures SLO-protected API calls breaching the 1s latency objective.",
        "event": "operation.completed",
        "priority": 35,
        "group_type": "slo-guardrails",
        "expression": {
            "op": "and",
            "args": [
                {
                    "op": "matches",
                    "left": {
                        "path": "$.request.path"
                    },
                    "right": "(?i)^/api/"
                },
                {
                    "op": ">=",
                    "left": {
                        "path": "$.timing.duration"
                    },
                    "right": 1000
                }
            ]
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "slo",
                        "slo.latency",
                        "slo.breach"
                    ]
                }
            }
        ]
    },
    {
        "id": "tmpl-slo-error-budget",
        "name": "SLO error budget hit",
        "description": "Highlights 5xx responses on SLO-protected APIs as error budget burns.",
        "event": "operation.completed",
        "priority": 30,
        "group_type": "slo-guardrails",
        "expression": {
            "op": "and",
            "args": [
                {
                    "op": "matches",
                    "left": {
                        "path": "$.request.path"
                    },
                    "right": "(?i)^/api/"
                },
                {
                    "op": "range",
                    "left": {
                        "path": "$.response.status"
                    },
                    "right": [
                        500,
                        599
                    ]
                }
            ]
        },
        "actions": [
            {
                "type": "tag",
                "params": {
                    "tags": [
                        "slo",
                        "slo.error",
                        "slo.error-budget"
                    ]
                }
            }
        ]
    }
]
export default templates;
