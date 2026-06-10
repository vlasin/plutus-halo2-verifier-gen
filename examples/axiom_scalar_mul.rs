use anyhow::{Context as _, Result};
use plutus_halo2_verifier_gen::plutus_gen::generate_axiom_scalar_mul_verifiers;
use std::{env, path::PathBuf};

fn main() -> Result<()> {
    let fixture = env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("../axiom-bls-secp-bench/target/cardano-secp-scalar-mul-fixture.json")
    });

    generate_axiom_scalar_mul_verifiers(&fixture).with_context(|| {
        format!(
            "failed to generate Axiom scalar-mul verifiers from {}",
            fixture.display()
        )
    })
}
