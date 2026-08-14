#!/usr/bin/env ruby
# Parses services/monitor-api/internal/api/openapi.yaml and resolves
# every local $ref in it.
#
# Nothing else in this repo does either. The spec is served as raw
# bytes (see internal/api/swagger.go, which embeds the file and hands
# it out verbatim -- deliberately, so the module needs no YAML
# dependency), and the only test that reads it,
# TestOpenAPISpec_DescribesEveryRegisteredRoute, is a substring grep
# over a golden list of route paths. So a spec with a broken indent, a
# duplicated key, or a $ref pointing at a schema that doesn't exist
# passes the entire suite: `curl /openapi.yaml` returns 200 with the
# bytes, and the failure only appears as a blank or broken page in
# somebody's browser, which is the one place nothing is watching.
#
# The two checks are separate failures, and the second is the one worth
# having a script for:
#
#   - YAML parses at all. Catches the mechanical damage -- a bad indent
#     in a hand-written block, a stray tab, an unquoted string that
#     parses as something else.
#   - Every "$ref: #/..." resolves to a node that exists. This is
#     invisible to a parse: a dangling $ref is perfectly valid YAML,
#     and Swagger UI renders it as an empty schema rather than an
#     error. Every response body in this spec is a $ref, so a typo in
#     one silently documents an endpoint as returning nothing.
#
# Deliberately NOT a full OpenAPI validator: that means a real
# dependency, and these two catch the failures this hand-written file
# actually has. Ruby because YAML is in its standard library -- no gem
# install, no lockfile, nothing to keep up to date.
#
# Run via `make check-openapi-spec` (containerized, no local Ruby
# needed).
require 'yaml'

SPEC = 'services/monitor-api/internal/api/openapi.yaml'.freeze

unless File.exist?(SPEC)
  abort "ERROR: #{SPEC} not found -- run this from the repository root"
end

begin
  # aliases: true because OpenAPI legitimately uses YAML anchors; the
  # rest of safe_load's restrictions (no arbitrary object
  # instantiation) are exactly what we want for a file we only read.
  spec = YAML.safe_load(File.read(SPEC), aliases: true)
rescue Psych::Exception => e
  abort "ERROR: #{SPEC} is not valid YAML:\n  #{e.message}"
end

unless spec.is_a?(Hash) && spec['openapi'] && spec['paths'].is_a?(Hash)
  abort "ERROR: #{SPEC} parsed, but has no top-level 'openapi' version and/or 'paths' map"
end

# Collect every $ref with the path it was found at, so a failure names
# the operation to go fix rather than just the broken target.
refs = []
walk = lambda do |node, trail|
  case node
  when Hash
    node.each do |key, value|
      if key == '$ref' && value.is_a?(String)
        refs << [value, trail.join('.')]
      else
        walk.call(value, trail + [key.to_s])
      end
    end
  when Array
    node.each_with_index { |value, i| walk.call(value, trail + ["[#{i}]"]) }
  end
end
walk.call(spec, [])

# resolve follows a "#/components/schemas/Stats" pointer through the
# parsed document. Local pointers only -- this spec has no external
# ones, and a $ref to another file would be a change worth noticing
# here rather than silently following.
def resolve(spec, ref)
  return false unless ref.start_with?('#/')

  node = spec
  ref.delete_prefix('#/').split('/').each do |segment|
    # RFC 6901 escapes, in case a key ever contains / or ~.
    segment = segment.gsub('~1', '/').gsub('~0', '~')
    return false unless node.is_a?(Hash) && node.key?(segment)

    node = node[segment]
  end
  true
end

broken = refs.reject { |ref, _| resolve(spec, ref) }
unless broken.empty?
  warn "ERROR: #{SPEC} has #{broken.length} unresolvable $ref(s):"
  broken.each { |ref, at| warn "  #{ref}   (referenced from #{at})" }
  warn 'A $ref that points at nothing is valid YAML and renders as an empty schema.'
  exit 1
end

puts "ok:   #{SPEC} parses (#{spec['paths'].length} paths, #{refs.length} $refs, all resolve)"
