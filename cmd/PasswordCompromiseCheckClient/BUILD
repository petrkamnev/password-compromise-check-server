load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_binary(
    name = "PasswordCompromiseCheckClient",
    out = "PasswordCompromiseCheckClient",
    srcs = ["main.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/PasswordCompromiseCheckClientLib",
    ],
)