load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = [
        "auth.go",
        "conn.go",
        "doc.go",
        "file.go",
        "request.go",
        "server.go",
        "session.go",
        "stack.go",
        "walk.go",
        "wstat.go",
    ],
    importpath = "aqwari.net/net/styx",
    visibility = ["//visibility:public"],
    deps = [
        "//aqwari.net/net/styx/internal/qidpool:go_default_library",
        "//aqwari.net/net/styx/internal/styxfile:go_default_library",
        "//aqwari.net/net/styx/internal/sys:go_default_library",
        "//aqwari.net/net/styx/internal/threadsafe:go_default_library",
        "//aqwari.net/net/styx/internal/tracing:go_default_library",
        "//aqwari.net/net/styx/internal/util:go_default_library",
        "//aqwari.net/net/styx/styxproto:go_default_library",
        "//aqwari.net/retry:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = ["server_test.go"],
    embed = [":go_default_library"],
    data = ["//aqwari.net/net/styx/styxproto:testdata"],
    deps = [
        "//aqwari.net/net/styx/internal/netutil:go_default_library",
        "//aqwari.net/net/styx/styxproto:go_default_library",
    ],
)

go_test(
    name = "go_default_xtest",
    srcs = [
        "example_stack_test.go",
        "example_test.go",
    ],
    deps = [":go_default_library"],
)
