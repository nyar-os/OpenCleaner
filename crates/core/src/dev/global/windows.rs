//! Windows global cache paths.

use std::path::PathBuf;

use crate::locations::BaseDirs;

use super::GlobalCacheSpec;
use crate::dev::rules::{Ecosystem, ManifestKind};

fn push(specs: &mut Vec<GlobalCacheSpec>, path: PathBuf, ecosystem: Ecosystem, anchor: ManifestKind, rule: &'static str) {
    specs.push(GlobalCacheSpec { path, ecosystem, anchor, rule });
}

pub(super) fn specs(dirs: &BaseDirs, env: impl Fn(&str) -> Option<String>) -> Vec<GlobalCacheSpec> {
    let mut specs = Vec::new();

    if let Some(cargo_home) = &dirs.cargo_home {
        push(&mut specs, cargo_home.join("registry"), Ecosystem::Cargo, ManifestKind::CargoToml, "Cargo.toml → cargo registry cache");
        push(&mut specs, cargo_home.join("git"), Ecosystem::Cargo, ManifestKind::CargoToml, "Cargo.toml → cargo git cache");
    }
    if let Some(local) = &dirs.local_app_data {
        push(&mut specs, local.join("npm-cache"), Ecosystem::Npm, ManifestKind::PackageJson, "package.json → npm cache");
        push(&mut specs, local.join("pnpm").join("store"), Ecosystem::Pnpm, ManifestKind::PnpmLock, "pnpm-lock.yaml → pnpm store");
        push(&mut specs, local.join("Yarn").join("Cache"), Ecosystem::Yarn, ManifestKind::YarnLock, "yarn.lock → yarn cache");
        push(&mut specs, local.join("pip").join("Cache"), Ecosystem::Python, ManifestKind::PyProject, "pyproject.toml → pip cache");
        push(&mut specs, local.join("uv").join("cache"), Ecosystem::Python, ManifestKind::PyProject, "pyproject.toml → uv cache");

        let go_cache = env("GOCACHE").filter(|value| !value.trim().is_empty()).map(PathBuf::from);
        push(&mut specs, go_cache.unwrap_or_else(|| local.join("go-build")), Ecosystem::Go, ManifestKind::GoMod, "go.mod → go build cache");
    }
    if let Some(home) = &dirs.home {
        let go_mod = env("GOMODCACHE")
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("go").join("pkg").join("mod"));
        push(&mut specs, go_mod, Ecosystem::Go, ManifestKind::GoMod, "go.mod → go module cache");

        push(&mut specs, home.join(".gradle").join("caches"), Ecosystem::Gradle, ManifestKind::Gradle, "build.gradle → gradle cache");
        push(&mut specs, home.join(".m2").join("repository"), Ecosystem::Maven, ManifestKind::Maven, "pom.xml → maven repository");
        push(&mut specs, home.join(".nuget").join("packages"), Ecosystem::Nuget, ManifestKind::Nuget, "*.csproj → nuget package cache");
    }

    dedupe(specs)
}

fn dedupe(specs: Vec<GlobalCacheSpec>) -> Vec<GlobalCacheSpec> {
    let mut seen = std::collections::BTreeSet::new();
    specs
        .into_iter()
        .filter(|spec| seen.insert(spec.path.clone()))
        .collect()
}
