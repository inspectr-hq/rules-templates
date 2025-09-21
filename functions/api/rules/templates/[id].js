import tpls from "./data";

const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "content-type"
};

export function onRequestGet(context) {
    const id = context.params.id;

    if (!id) {
        return new Response("Not found", { status: 404, headers: corsHeaders });
    }

    const template = tpls.find((template) => template.id === id);

    if (!template) {
        return new Response("Not found", { status: 404, headers: corsHeaders });
    }

    return Response.json(template, { headers: corsHeaders });
}

export function onRequestOptions() {
    return new Response(null, { status: 204, headers: corsHeaders });
}
