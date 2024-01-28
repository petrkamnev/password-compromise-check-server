load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = ["main.go"],
    importpath = "github.com/openmined/psi",
    deps = [
            "@org_golang_google_protobuf//proto:go_default_library",
            "@org_openmined_psi//private_set_intersection/go/server",
            "@org_openmined_psi//private_set_intersection/go/client",
            "@org_openmined_psi//private_set_intersection/go/datastructure",
            "@org_openmined_psi//private_set_intersection/proto:psi_go_proto",
            ],
)

go_binary(
    name = "PasswordCompromiseCheckClient",
    out = "PasswordCompromiseCheckClient",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
    deps = [
        "@org_golang_google_protobuf//proto:go_default_library",
    ]
)