load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["trace.go"],
    importpath = "aqwari.net/net/styx/internal/tracing",
    visibility = ["//aqwari.net/net/styx:__subpackages__"],
    deps = ["//aqwari.net/net/styx/styxproto:go_default_library"],
)

go_test(
    name = "go_default_test",
    srcs = ["tracing_test.go"],
    embed = [":go_default_library"],
)
