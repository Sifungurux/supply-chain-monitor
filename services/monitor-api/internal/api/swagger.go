package api

import (
	_ "embed"
	"net/http"
)

// openapiSpecYAML is the OpenAPI 3.0 document describing every route this
// package registers -- kept as a plain YAML file (openapi.yaml) rather
// than generated from struct/handler annotations, since this module's own
// go.mod deliberately keeps pgx as "the one non-stdlib dependency": a
// codegen library (e.g. swaggo/swag) would be a second one just for this.
// go:embed bakes the file into the binary at build time, so serving it
// needs no filesystem access at runtime and can't drift from whatever was
// actually committed.
//
//go:embed openapi.yaml
var openapiSpecYAML []byte

// swaggerUIHTML loads Swagger UI from jsDelivr and points it at
// /openapi.yaml -- the same CDN-for-UI-assets approach dashboard/index.html
// already uses for its icon font, so this doesn't introduce a new pattern
// to the repo. Pinned to an exact version (not a floating tag like `@5`)
// with a Subresource Integrity hash on every <script>/<link>: a floating
// version can't be hashed at all (the bytes it resolves to change out from
// under the hash on every new release), and this is, after all, a supply
// chain security tool -- loading its own UI from a CDN with no integrity
// check would be exactly the kind of unpinned dependency this project
// exists to flag in everyone else's software. Hashes computed directly
// from the fetched files (sha384sum-equivalent via openssl), not copied
// from anywhere. Swagger UI's own "Authorize" button is where a caller
// enters the bearer API key needed for every route except /healthz and
// these two docs routes themselves; this page has no server-side
// templating to do at all.
const swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Supply chain monitor API</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css"
  integrity="sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn" crossorigin="anonymous" />
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"
  integrity="sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-standalone-preset.js"
  integrity="sha384-2YH8WDRaj7V2OqU/trsmzSagmk/E2SutiCsGkdgoQwC9pNUJV1u/141DHB6jgs8t" crossorigin="anonymous"></script>
<script>
  window.onload = function () {
    SwaggerUIBundle({
      url: '/openapi.yaml',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
      layout: 'StandaloneLayout'
    });
  };
</script>
</body>
</html>
`

func (h *handler) swaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerUIHTML))
}

func (h *handler) openapiSpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(openapiSpecYAML)
}
