import tpls from "./data";

export function onRequestGet(context) {
    const id = context.params.id;

    if (!id) {
        return new Response("Not found", { status: 404 });
    }

    const template = tpls.find((template) => template.id === id);

    if (!template) {
        return new Response("Not found", { status: 404 });
    }

    return Response.json(template);
}
