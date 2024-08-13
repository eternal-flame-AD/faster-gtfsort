use vergen::{BuildBuilder, CargoBuilder, Emitter};
use vergen_git2::Git2Builder;

fn main() {
    let build = BuildBuilder::all_build().expect("Unable to create build info");
    let cargo = CargoBuilder::all_cargo().expect("Unable to get cargo info");
    let git = Git2Builder::all_git().expect("Unable to get git info");

    Emitter::default()
        .add_instructions(&build)
        .expect("Unable to add build instructions")
        .add_instructions(&cargo)
        .expect("Unable to add cargo instructions")
        .add_instructions(&git)
        .expect("Unable to add git instructions")
        .emit()
        .expect("Unable to emit vergen instructions");

    println!("cargo:rerun-if-changed=build.rs");
}
