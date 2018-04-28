load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "doc.go",
        "group_go17.go",
        "group_oldgo.go",
        "owner.go",
        "owner_fallback.go",
        "owner_plan9.go",
        "owner_unix.go",
    ],
    importpath = "aqwari.net/net/styx/internal/sys",
    visibility = ["//aqwari.net/net/styx:__subpackages__"],
    deps = [
        "//aqwari.net/net/styx/styxproto:go_default_library",
    ],
)
