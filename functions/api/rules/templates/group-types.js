import { template_group_types } from "./data";

const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "content-type"
};

export function onRequestGet() {
    return Response.json(template_group_types, { headers: corsHeaders });
}

export function onRequestOptions() {
    return new Response(null, { status: 204, headers: corsHeaders });
}
