load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")
load("@bazel_gazelle//:def.bzl", "gazelle")
gazelle(name = "gazelle")

gazelle(
    name = "gazelle-update-repos",
    args = [
        "-from_file=go.mod",
        "-to_macro=deps.bzl%go_dependencies",
        "-prune",
    ],
    command = "update-repos",
)

go_library(
    name = "PasswordCompromiseCheckClient_lib",
    srcs = ["main.go"],
    importpath = "PasswordCompromiseCheckClient",
    visibility = ["//visibility:private"],
    deps = [
        "@com_github_avast_retry_go//:retry-go",
        "@com_github_schollz_progressbar_v3//:progressbar",
    ],
)
go_binary(
    name = "PasswordCompromiseCheckClient",
    out = "PasswordCompromiseCheckClient",
    visibility = ["//visibility:public"],
    embed = [":PasswordCompromiseCheckClient_lib"],
    deps = [
        "//pkg/PasswordCompromiseCheckClientLib",
    ],
)