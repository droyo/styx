load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = [
        "dir.go",
        "dumb.go",
        "file.go",
        "mode.go",
        "seeker.go",
    ],
    importpath = "aqwari.net/net/styx/internal/styxfile",
    visibility = ["//aqwari.net/net/styx:__subpackages__"],
    deps = [
        "//aqwari.net/net/styx/internal/qidpool:go_default_library",
        "//aqwari.net/net/styx/internal/sys:go_default_library",
        "//aqwari.net/net/styx/styxproto:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = [
        "file_test.go",
        "mode_test.go",
    ],
    embed = [":go_default_library"],
    deps = [
        "//aqwari.net/net/styx/internal/qidpool:go_default_library",
        "//aqwari.net/net/styx/styxproto:go_default_library",
    ],
)
