load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = ["main.go"],
    importpath = "github.com/openmined/psi",
    deps = [
            "@org_openmined_psi//private_set_intersection/go/server",
            "@org_openmined_psi//private_set_intersection/go/client",
            ],
)

go_binary(
    name = "PasswordCompromiseCheckServer",
    out = "PasswordCompromiseCheckServer",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
)