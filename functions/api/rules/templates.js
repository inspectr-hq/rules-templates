import templates from "./templates/data";

export function onRequestGet() {
    return Response.json(templates);
}