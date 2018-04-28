load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "auth.go",
        "doc.go",
        "socket.go",
        "tls.go",
    ],
    importpath = "aqwari.net/net/styx/styxauth",
    visibility = ["//visibility:public"],
    deps = [
        "//aqwari.net/net/styx:go_default_library",
    ],
)
