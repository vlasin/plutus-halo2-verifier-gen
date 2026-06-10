//! Source-only generator for the Axiom Halo2 scalar-multiplication verifier.
//!
//! This module intentionally emits generated verifier files into the same
//! ignored output locations as the existing IOG-Halo2 generator. The source of
//! truth is the Axiom verifier fixture plus the templates tracked in this repo.

use anyhow::{Context as _, Result, ensure};
use handlebars::Handlebars;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
};

const DEFAULT_AIKEN_TEMPLATE: &str = "aiken-verifier/templates/axiom_scalar_mul.hbs";
const DEFAULT_AIKEN_OUTPUT: &str = "aiken-verifier/aiken_halo2/lib/proof_verifier.ak";
const DEFAULT_AIKEN_VK_TEMPLATE: &str = "aiken-verifier/templates/axiom_verifier_key_stub.hbs";
const DEFAULT_AIKEN_VK_OUTPUT: &str = "aiken-verifier/aiken_halo2/lib/verifier_key.ak";
const DEFAULT_PLINTH_TEMPLATE: &str = "plinth-verifier/templates/axiom_scalar_mul.hbs";
const DEFAULT_PLINTH_OUTPUT: &str =
    "plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs";
const DEFAULT_PLINTH_TEST_TEMPLATE: &str = "plinth-verifier/templates/axiom_scalar_mul_test.hbs";
const DEFAULT_PLINTH_TEST_OUTPUT: &str =
    "plinth-verifier/plutus-halo2/test/Generic/VerificationTestPlutus.hs";
const DEFAULT_PLINTH_TEST_MAIN_TEMPLATE: &str =
    "plinth-verifier/templates/axiom_scalar_mul_test_main.hbs";
const DEFAULT_PLINTH_TEST_MAIN_OUTPUT: &str = "plinth-verifier/plutus-halo2/test/Test.hs";
const DEFAULT_PLINTH_HASKELL_TEST_TEMPLATE: &str =
    "plinth-verifier/templates/axiom_scalar_mul_test_haskell.hbs";
const DEFAULT_PLINTH_HASKELL_TEST_OUTPUT: &str =
    "plinth-verifier/plutus-halo2/test/Generic/VerificationTestHaskell.hs";
const DEFAULT_PLINTH_COMPILED_STUB_TEMPLATE: &str =
    "plinth-verifier/templates/axiom_scalar_mul_verify_compiled.hbs";
const DEFAULT_PLINTH_COMPILED_STUB_OUTPUT: &str =
    "plinth-verifier/plutus-halo2/test/Generic/VerifyCompiled.hs";

/// Axiom scalar multiplication fixture exported by the benchmark/prover side.
#[derive(Debug, Deserialize)]
pub struct AxiomScalarMulFixture {
    backend: String,
    curve: String,
    pcs: String,
    transcript: String,
    proof_hex: String,
    n: u64,
    k: u32,
    quotient_poly_degree: usize,
    blinding_factors: usize,
    omega: String,
    omega_inv: String,
    barycentric_weight: String,
    transcript_repr: String,
    s_g2: String,
    fixed_commitments: Vec<String>,
    permutation_commitments: Vec<String>,
    shape: AxiomScalarMulShape,
}

#[derive(Debug, Deserialize)]
struct AxiomScalarMulShape {
    num_fixed_columns: usize,
    num_advice_columns: usize,
    num_instance_columns: usize,
    advice_queries: Vec<ColumnRotation>,
    fixed_queries: Vec<ColumnRotation>,
    permutation_columns: Vec<PermutationColumn>,
    lookup: LookupShape,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ColumnRotation {
    column: usize,
    rotation: i32,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct PermutationColumn {
    #[serde(rename = "type")]
    column_type: String,
    column: usize,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct LookupShape {
    input: TypedColumnRotation,
    table: TypedColumnRotation,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct TypedColumnRotation {
    #[serde(rename = "type")]
    column_type: String,
    column: usize,
    rotation: i32,
}

/// Output locations used by the Axiom scalar-mul generator.
#[derive(Clone, Debug)]
pub struct AxiomScalarMulOutputPaths {
    pub aiken_template: PathBuf,
    pub aiken_output: PathBuf,
    pub aiken_vk_template: PathBuf,
    pub aiken_vk_output: PathBuf,
    pub plinth_template: PathBuf,
    pub plinth_output: PathBuf,
    pub plinth_test_template: PathBuf,
    pub plinth_test_output: PathBuf,
    pub plinth_test_main_template: PathBuf,
    pub plinth_test_main_output: PathBuf,
    pub plinth_haskell_test_template: PathBuf,
    pub plinth_haskell_test_output: PathBuf,
    pub plinth_compiled_stub_template: PathBuf,
    pub plinth_compiled_stub_output: PathBuf,
}

impl Default for AxiomScalarMulOutputPaths {
    fn default() -> Self {
        Self {
            aiken_template: DEFAULT_AIKEN_TEMPLATE.into(),
            aiken_output: DEFAULT_AIKEN_OUTPUT.into(),
            aiken_vk_template: DEFAULT_AIKEN_VK_TEMPLATE.into(),
            aiken_vk_output: DEFAULT_AIKEN_VK_OUTPUT.into(),
            plinth_template: DEFAULT_PLINTH_TEMPLATE.into(),
            plinth_output: DEFAULT_PLINTH_OUTPUT.into(),
            plinth_test_template: DEFAULT_PLINTH_TEST_TEMPLATE.into(),
            plinth_test_output: DEFAULT_PLINTH_TEST_OUTPUT.into(),
            plinth_test_main_template: DEFAULT_PLINTH_TEST_MAIN_TEMPLATE.into(),
            plinth_test_main_output: DEFAULT_PLINTH_TEST_MAIN_OUTPUT.into(),
            plinth_haskell_test_template: DEFAULT_PLINTH_HASKELL_TEST_TEMPLATE.into(),
            plinth_haskell_test_output: DEFAULT_PLINTH_HASKELL_TEST_OUTPUT.into(),
            plinth_compiled_stub_template: DEFAULT_PLINTH_COMPILED_STUB_TEMPLATE.into(),
            plinth_compiled_stub_output: DEFAULT_PLINTH_COMPILED_STUB_OUTPUT.into(),
        }
    }
}

/// Generate both Aiken and Plinth verifier sources from an Axiom fixture.
pub fn generate_axiom_scalar_mul_verifiers(fixture_path: &Path) -> Result<()> {
    generate_axiom_scalar_mul_verifiers_with_paths(
        fixture_path,
        &AxiomScalarMulOutputPaths::default(),
    )
}

/// Generate both Aiken and Plinth verifier sources from an Axiom fixture into
/// caller-provided output paths.
pub fn generate_axiom_scalar_mul_verifiers_with_paths(
    fixture_path: &Path,
    paths: &AxiomScalarMulOutputPaths,
) -> Result<()> {
    let fixture = read_fixture(fixture_path)?;
    fixture.validate()?;
    let data = fixture.template_data()?;

    render_template(&paths.aiken_template, &paths.aiken_output, &data)
        .context("failed to render Axiom scalar-mul Aiken verifier")?;
    render_template(&paths.aiken_vk_template, &paths.aiken_vk_output, &data)
        .context("failed to render Axiom scalar-mul Aiken verifier key stub")?;
    render_template(&paths.plinth_template, &paths.plinth_output, &data)
        .context("failed to render Axiom scalar-mul Plinth verifier")?;
    render_template(
        &paths.plinth_test_template,
        &paths.plinth_test_output,
        &data,
    )
    .context("failed to render Axiom scalar-mul Plinth benchmark test")?;
    render_template(
        &paths.plinth_test_main_template,
        &paths.plinth_test_main_output,
        &data,
    )
    .context("failed to render Axiom scalar-mul Plinth test main")?;
    render_template(
        &paths.plinth_haskell_test_template,
        &paths.plinth_haskell_test_output,
        &data,
    )
    .context("failed to render Axiom scalar-mul Haskell verifier test")?;
    render_template(
        &paths.plinth_compiled_stub_template,
        &paths.plinth_compiled_stub_output,
        &data,
    )
    .context("failed to render Axiom scalar-mul compiled verifier stub")?;

    Ok(())
}

fn read_fixture(path: &Path) -> Result<AxiomScalarMulFixture> {
    let file = File::open(path)
        .with_context(|| format!("failed to open Axiom fixture {}", path.display()))?;
    serde_json::from_reader(file)
        .with_context(|| format!("failed to parse Axiom fixture {}", path.display()))
}

fn render_template(
    template_path: &Path,
    output_path: &Path,
    data: &HashMap<String, String>,
) -> Result<String> {
    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars
        .register_template_file("template", template_path)
        .with_context(|| format!("failed to register template {}", template_path.display()))?;
    let mut output = File::create(output_path)
        .with_context(|| format!("failed to create generated file {}", output_path.display()))?;
    handlebars
        .render_to_write("template", data, &mut output)
        .with_context(|| format!("failed to render {}", output_path.display()))?;
    handlebars
        .render("template", data)
        .context("failed to render template to string")
}

impl AxiomScalarMulFixture {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.backend.starts_with("halo2-axiom"),
            "unsupported Axiom backend {}",
            self.backend
        );
        ensure!(
            self.curve == "bls12_381",
            "unsupported curve {}",
            self.curve
        );
        ensure!(self.pcs == "kzg-shplonk", "unsupported PCS {}", self.pcs);
        ensure!(
            self.transcript == "cardano-friendly-blake2b-256",
            "unsupported transcript {}",
            self.transcript
        );
        ensure!(self.k == 18, "unsupported scalar-mul fixture k {}", self.k);
        ensure!(
            self.n == 262_144,
            "unsupported scalar-mul fixture n {}",
            self.n
        );
        ensure!(
            self.quotient_poly_degree == 3,
            "unsupported quotient polynomial degree {}",
            self.quotient_poly_degree
        );
        ensure!(
            self.blinding_factors == 6,
            "unsupported blinding factors {}",
            self.blinding_factors
        );
        ensure!(
            self.fixed_commitments.len() == 4,
            "expected 4 fixed commitments, got {}",
            self.fixed_commitments.len()
        );
        ensure!(
            self.permutation_commitments.len() == 4,
            "expected 4 permutation commitments, got {}",
            self.permutation_commitments.len()
        );
        self.shape.validate()
    }

    fn template_data(&self) -> Result<HashMap<String, String>> {
        let mut data = HashMap::new();
        data.insert("N".to_string(), self.n.to_string());
        data.insert(
            "BLINDING_FACTORS".to_string(),
            self.blinding_factors.to_string(),
        );
        data.insert("TRANSCRIPT_REP".to_string(), self.transcript_repr.clone());
        data.insert("OMEGA".to_string(), self.omega.clone());
        data.insert("OMEGA_INV".to_string(), self.omega_inv.clone());
        data.insert(
            "BARYCENTRIC_WEIGHT".to_string(),
            self.barycentric_weight.clone(),
        );
        data.insert("S_G2_CARDANO".to_string(), reverse_hex_bytes(&self.s_g2)?);
        data.insert("PROOF_HEX".to_string(), self.proof_hex.clone());

        for (idx, commitment) in self.fixed_commitments.iter().enumerate() {
            data.insert(format!("FIXED_{idx}"), commitment.clone());
        }
        for (idx, commitment) in self.permutation_commitments.iter().enumerate() {
            data.insert(format!("PERMUTATION_COMMON_{idx}"), commitment.clone());
        }

        Ok(data)
    }
}

impl AxiomScalarMulShape {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.num_fixed_columns == 4,
            "expected 4 fixed columns, got {}",
            self.num_fixed_columns
        );
        ensure!(
            self.num_advice_columns == 3,
            "expected 3 advice columns, got {}",
            self.num_advice_columns
        );
        ensure!(
            self.num_instance_columns == 0,
            "expected no instance columns, got {}",
            self.num_instance_columns
        );
        ensure!(
            self.advice_queries
                == [
                    ColumnRotation {
                        column: 0,
                        rotation: 0
                    },
                    ColumnRotation {
                        column: 0,
                        rotation: 1
                    },
                    ColumnRotation {
                        column: 0,
                        rotation: 2
                    },
                    ColumnRotation {
                        column: 0,
                        rotation: 3
                    },
                    ColumnRotation {
                        column: 1,
                        rotation: 0
                    },
                    ColumnRotation {
                        column: 1,
                        rotation: 1
                    },
                    ColumnRotation {
                        column: 1,
                        rotation: 2
                    },
                    ColumnRotation {
                        column: 1,
                        rotation: 3
                    },
                    ColumnRotation {
                        column: 2,
                        rotation: 0
                    },
                ],
            "unsupported advice query shape"
        );
        ensure!(
            self.fixed_queries
                == [
                    ColumnRotation {
                        column: 1,
                        rotation: 0
                    },
                    ColumnRotation {
                        column: 0,
                        rotation: 0
                    },
                    ColumnRotation {
                        column: 2,
                        rotation: 0
                    },
                    ColumnRotation {
                        column: 3,
                        rotation: 0
                    },
                ],
            "unsupported fixed query shape"
        );
        ensure!(
            self.permutation_columns
                == [
                    PermutationColumn {
                        column_type: "fixed".to_string(),
                        column: 1,
                    },
                    PermutationColumn {
                        column_type: "advice".to_string(),
                        column: 0,
                    },
                    PermutationColumn {
                        column_type: "advice".to_string(),
                        column: 1,
                    },
                    PermutationColumn {
                        column_type: "advice".to_string(),
                        column: 2,
                    },
                ],
            "unsupported permutation column shape"
        );
        ensure!(
            self.lookup
                == LookupShape {
                    input: TypedColumnRotation {
                        column_type: "advice".to_string(),
                        column: 2,
                        rotation: 0,
                    },
                    table: TypedColumnRotation {
                        column_type: "fixed".to_string(),
                        column: 0,
                        rotation: 0,
                    },
                },
            "unsupported lookup shape"
        );
        Ok(())
    }
}

fn reverse_hex_bytes(hex_value: &str) -> Result<String> {
    ensure!(hex_value.len() % 2 == 0, "hex string has odd length");
    let mut bytes = hex::decode(hex_value).context("failed to decode hex bytes")?;
    bytes.reverse();
    Ok(hex::encode(bytes))
}
