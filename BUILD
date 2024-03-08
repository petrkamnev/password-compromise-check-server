load("@bazel_gazelle//:def.bzl", "gazelle")

# gazelle:prefix PasswordCompromiseCheckProject

gazelle(name = "gazelle")

load("@io_bazel_rules_go//go:def.bzl", "go_binary")

filegroup(
    name = "all_modules",
    srcs = [
        "//cmd/CompromisedPasswordsImporter",
        "//cmd/PasswordCompromiseCheckClient",
        "//cmd/PasswordCompromiseCheckServer",
    ],
    visibility = ["//visibility:public"],
)
