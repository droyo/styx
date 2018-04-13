load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "doc.go",
        "group_go17.go",
        "group_oldgo.go",
        "owner.go",
    ] + select({
        "@io_bazel_rules_go//go/platform:android": [
            "owner_unix.go",
        ],
        "@io_bazel_rules_go//go/platform:darwin": [
            "owner_unix.go",
        ],
        "@io_bazel_rules_go//go/platform:dragonfly": [
            "owner_unix.go",
        ],
        "@io_bazel_rules_go//go/platform:freebsd": [
            "owner_unix.go",
        ],
        "@io_bazel_rules_go//go/platform:linux": [
            "owner_unix.go",
        ],
        "@io_bazel_rules_go//go/platform:nacl": [
            "owner_unix.go",
        ],
        "@io_bazel_rules_go//go/platform:netbsd": [
            "owner_unix.go",
        ],
        "@io_bazel_rules_go//go/platform:openbsd": [
            "owner_unix.go",
        ],
        "@io_bazel_rules_go//go/platform:plan9": [
            "owner_plan9.go",
        ],
        "@io_bazel_rules_go//go/platform:solaris": [
            "owner_unix.go",
        ],
        "@io_bazel_rules_go//go/platform:windows": [
            "owner_fallback.go",
        ],
        "//conditions:default": [],
    }),
    importpath = "aqwari.net/net/styx/internal/sys",
    visibility = ["//aqwari.net/net/styx:__subpackages__"],
    deps = [
        "//aqwari.net/net/styx/styxproto:go_default_library",
    ],
)
