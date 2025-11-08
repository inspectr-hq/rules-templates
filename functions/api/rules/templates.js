import templates from './templates/data';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type'
};

export function onRequestGet() {
  return Response.json(templates, { headers: corsHeaders });
}

export function onRequestOptions() {
  return new Response(null, { status: 204, headers: corsHeaders });
}
