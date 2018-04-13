load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["pool.go"],
    importpath = "aqwari.net/net/styx/internal/qidpool",
    visibility = ["//aqwari.net/net/styx:__subpackages__"],
    deps = [
        "//aqwari.net/net/styx/internal/threadsafe:go_default_library",
        "//aqwari.net/net/styx/styxproto:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = ["pool_test.go"],
    embed = [":go_default_library"],
    deps = ["//aqwari.net/net/styx/styxproto:go_default_library"],
)
