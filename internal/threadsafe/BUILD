load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["map.go"],
    importpath = "aqwari.net/net/styx/internal/threadsafe",
    visibility = ["//aqwari.net/net/styx:__subpackages__"],
)

go_test(
    name = "go_default_test",
    srcs = ["map_test.go"],
    embed = [":go_default_library"],
)
