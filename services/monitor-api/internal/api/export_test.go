package api

// Test-only exports.
//
// validFindingsBucket is deliberately unexported -- the five-string
// vocabulary is an API-contract detail of this package, not something
// other packages should branch on. But internal/policy has to
// duplicate that list (it cannot import this package without a cycle,
// since this package imports it), and a duplicate is only safe when a
// test asserts the two agree. See TestPolicyBucketsMatchAPI.
var ValidFindingsBucketForTest = validFindingsBucket
