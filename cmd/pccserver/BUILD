load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = ["main.go", "root.go", "server.go", "state.go", "storage.go"],
    importpath = "github.com/openmined/psi",
    deps = [
            "@org_golang_google_protobuf//proto:go_default_library",
            "@org_openmined_psi//private_set_intersection/go/server",
            "@org_openmined_psi//private_set_intersection/go/client",
            "@org_openmined_psi//private_set_intersection/go/datastructure",
            "@org_openmined_psi//private_set_intersection/proto:psi_go_proto",
            "@com_github_spf13_cobra//:go_default_library",
            "@com_github_avast_retry_go//:retry-go",
            "@com_github_schollz_progressbar_v3//:progressbar",
            "@com_github_pkg_xattr//:go_default_library"
            ],
)

go_binary(
    name = "pccserver",
    out = "pccserver",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
    deps = [
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)