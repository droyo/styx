load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "auth.go",
        "doc.go",
        "tls.go",
    ] + select({
        "@io_bazel_rules_go//go/platform:linux": [
            "socket.go",
        ],
        "//conditions:default": [],
    }),
    importpath = "aqwari.net/net/styx/styxauth",
    visibility = ["//visibility:public"],
    deps = [
        "//aqwari.net/net/styx:go_default_library",
    ],
)
