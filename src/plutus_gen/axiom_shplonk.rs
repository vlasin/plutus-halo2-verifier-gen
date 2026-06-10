//! Source-only generator for Axiom Halo2 SHPLONK verifiers.
//!
//! This module emits generated verifier files into the same ignored output
//! locations as the existing IOG-Halo2 generator. The source of truth is the
//! Axiom proving artifacts: parameters, verifying key, and proof bytes.

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use halo2_axiom::{
    halo2curves::{
        bls12_381::{Bls12, Fr as BlsFr, G1Affine, G2Affine},
        ff::PrimeField as _,
        group::GroupEncoding as _,
    },
    plonk::{Any, Circuit, Expression, VerifyingKey, keygen_vk},
    poly::kzg::commitment::ParamsKZG,
};
use handlebars::Handlebars;
use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    path::{Path, PathBuf},
};

const DEFAULT_AIKEN_TEMPLATE: &str = "aiken-verifier/templates/axiom_shplonk.hbs";
const DEFAULT_AIKEN_OUTPUT: &str = "aiken-verifier/aiken_halo2/lib/proof_verifier.ak";
const DEFAULT_AIKEN_VK_TEMPLATE: &str = "aiken-verifier/templates/axiom_verifier_key_stub.hbs";
const DEFAULT_AIKEN_VK_OUTPUT: &str = "aiken-verifier/aiken_halo2/lib/verifier_key.ak";
const DEFAULT_PLINTH_TEMPLATE: &str = "plinth-verifier/templates/axiom_shplonk.hbs";
const DEFAULT_PLINTH_OUTPUT: &str =
    "plinth-verifier/plutus-halo2/src/Plutus/Crypto/Halo2/Generic/Verifier.hs";
const DEFAULT_PLINTH_TEST_TEMPLATE: &str = "plinth-verifier/templates/axiom_proof_test.hbs";
const DEFAULT_PLINTH_TEST_OUTPUT: &str =
    "plinth-verifier/plutus-halo2/test/Generic/VerificationTestPlutus.hs";
const DEFAULT_PLINTH_TEST_MAIN_TEMPLATE: &str =
    "plinth-verifier/templates/axiom_proof_test_main.hbs";
const DEFAULT_PLINTH_TEST_MAIN_OUTPUT: &str = "plinth-verifier/plutus-halo2/test/Test.hs";
const DEFAULT_PLINTH_HASKELL_TEST_TEMPLATE: &str =
    "plinth-verifier/templates/axiom_proof_test_haskell.hbs";
const DEFAULT_PLINTH_HASKELL_TEST_OUTPUT: &str =
    "plinth-verifier/plutus-halo2/test/Generic/VerificationTestHaskell.hs";
const DEFAULT_PLINTH_COMPILED_STUB_TEMPLATE: &str =
    "plinth-verifier/templates/axiom_verify_compiled_stub.hbs";
const DEFAULT_PLINTH_COMPILED_STUB_OUTPUT: &str =
    "plinth-verifier/plutus-halo2/test/Generic/VerifyCompiled.hs";

/// Output locations used by the Axiom SHPLONK generator.
#[derive(Clone, Debug)]
pub struct AxiomShplonkOutputPaths {
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

impl Default for AxiomShplonkOutputPaths {
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

/// Generate both Aiken and Plinth verifier sources from Axiom proving artifacts.
pub fn generate_axiom_shplonk_verifiers_from_vk(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<G1Affine>,
    proof: &[u8],
) -> Result<()> {
    generate_axiom_shplonk_verifiers_from_vk_with_paths(
        params,
        vk,
        proof,
        &AxiomShplonkOutputPaths::default(),
    )
}

/// Generate both Aiken and Plinth verifier sources from Axiom proving artifacts
/// into caller-provided output paths.
pub fn generate_axiom_shplonk_verifiers_from_vk_with_paths(
    params: &ParamsKZG<Bls12>,
    vk: &VerifyingKey<G1Affine>,
    proof: &[u8],
    paths: &AxiomShplonkOutputPaths,
) -> Result<()> {
    let render_data = AxiomShplonkRenderData::from_vk_and_proof(params, vk, proof)?;
    render_axiom_shplonk_verifiers(&render_data.data, paths)
}

/// Generate both Aiken and Plinth verifier sources from an Axiom circuit and
/// proof bytes.
pub fn generate_axiom_shplonk_verifiers_from_circuit<ConcreteCircuit>(
    params: &ParamsKZG<Bls12>,
    circuit: &ConcreteCircuit,
    proof: &[u8],
) -> Result<()>
where
    ConcreteCircuit: Circuit<BlsFr>,
{
    generate_axiom_shplonk_verifiers_from_circuit_with_paths(
        params,
        circuit,
        proof,
        &AxiomShplonkOutputPaths::default(),
    )
}

/// Generate both Aiken and Plinth verifier sources from an Axiom circuit and
/// proof bytes into caller-provided output paths.
pub fn generate_axiom_shplonk_verifiers_from_circuit_with_paths<ConcreteCircuit>(
    params: &ParamsKZG<Bls12>,
    circuit: &ConcreteCircuit,
    proof: &[u8],
    paths: &AxiomShplonkOutputPaths,
) -> Result<()>
where
    ConcreteCircuit: Circuit<BlsFr>,
{
    let vk = keygen_vk::<G1Affine, _, _>(params, circuit)
        .map_err(|err| anyhow!("failed to generate Axiom verifying key: {err:?}"))?;
    generate_axiom_shplonk_verifiers_from_vk_with_paths(params, &vk, proof, paths)
}

fn render_axiom_shplonk_verifiers(
    data: &HashMap<String, String>,
    paths: &AxiomShplonkOutputPaths,
) -> Result<()> {
    render_template(&paths.aiken_template, &paths.aiken_output, data)
        .context("failed to render Axiom SHPLONK Aiken verifier")?;
    render_template(&paths.aiken_vk_template, &paths.aiken_vk_output, data)
        .context("failed to render Axiom SHPLONK Aiken verifier key stub")?;
    render_template(&paths.plinth_template, &paths.plinth_output, data)
        .context("failed to render Axiom SHPLONK Plinth verifier")?;
    render_template(&paths.plinth_test_template, &paths.plinth_test_output, data)
        .context("failed to render Axiom SHPLONK Plinth benchmark test")?;
    render_template(
        &paths.plinth_test_main_template,
        &paths.plinth_test_main_output,
        data,
    )
    .context("failed to render Axiom SHPLONK Plinth test main")?;
    render_template(
        &paths.plinth_haskell_test_template,
        &paths.plinth_haskell_test_output,
        data,
    )
    .context("failed to render Axiom SHPLONK Haskell verifier test")?;
    render_template(
        &paths.plinth_compiled_stub_template,
        &paths.plinth_compiled_stub_output,
        data,
    )
    .context("failed to render Axiom SHPLONK compiled verifier stub")?;

    Ok(())
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

struct AxiomShplonkRenderData {
    data: HashMap<String, String>,
}

impl AxiomShplonkRenderData {
    fn from_vk_and_proof(
        params: &ParamsKZG<Bls12>,
        vk: &VerifyingKey<G1Affine>,
        proof: &[u8],
    ) -> Result<Self> {
        let layout = AxiomLayout::from_vk(vk)?;
        let domain = vk.get_domain();
        let n = domain.get_n();
        let barycentric_weight = BlsFr::from(n)
            .invert()
            .into_option()
            .context("evaluation domain size has no inverse")?;
        let fixed_commitments = vk
            .fixed_commitments()
            .iter()
            .copied()
            .map(g1_hex)
            .collect::<Vec<_>>();
        let permutation_commitments = vk
            .permutation()
            .commitments()
            .iter()
            .copied()
            .map(g1_hex)
            .collect::<Vec<_>>();

        let mut data = HashMap::new();
        data.insert("N".to_string(), n.to_string());
        data.insert(
            "BLINDING_FACTORS".to_string(),
            layout.blinding_factors.to_string(),
        );
        data.insert(
            "TRANSCRIPT_REP".to_string(),
            scalar_hex(vk.transcript_repr()),
        );
        data.insert("OMEGA".to_string(), scalar_hex(domain.get_omega()));
        data.insert("OMEGA_INV".to_string(), scalar_hex(domain.get_omega_inv()));
        data.insert(
            "BARYCENTRIC_WEIGHT".to_string(),
            scalar_hex(barycentric_weight),
        );
        data.insert(
            "S_G2_CARDANO".to_string(),
            reverse_hex_bytes(&g2_hex(params.s_g2()))?,
        );
        data.insert("PROOF_HEX".to_string(), hex::encode(proof));
        data.insert(
            "AIKEN_FIXED_COMMITMENTS".to_string(),
            aiken_fixed_commitments(&fixed_commitments),
        );
        data.insert(
            "AIKEN_PERMUTATION_COMMITMENTS".to_string(),
            aiken_permutation_commitments(&permutation_commitments),
        );
        data.insert(
            "AIKEN_PROOF_FIELDS".to_string(),
            layout.aiken_proof_fields(),
        );
        data.insert("AIKEN_PARSE_PROOF".to_string(), layout.aiken_parse_proof());
        data.insert(
            "AIKEN_EXPECTED_H_EVAL".to_string(),
            layout.aiken_expected_h_eval(vk)?,
        );
        data.insert(
            "AIKEN_SHPLONK_PAIRING_CHECK".to_string(),
            layout.aiken_shplonk_pairing_check(),
        );
        data.insert(
            "AIKEN_VANISHING_H_MSM".to_string(),
            layout.aiken_vanishing_h_msm(),
        );
        data.insert(
            "PLINTH_FIXED_COMMITMENTS".to_string(),
            plinth_fixed_commitments(&fixed_commitments),
        );
        data.insert(
            "PLINTH_PERMUTATION_COMMITMENTS".to_string(),
            plinth_permutation_commitments(&permutation_commitments),
        );
        data.insert(
            "PLINTH_PROOF_FIELDS".to_string(),
            layout.plinth_proof_fields(),
        );
        data.insert(
            "PLINTH_PARSE_PROOF".to_string(),
            layout.plinth_parse_proof(),
        );
        data.insert(
            "PLINTH_EXPECTED_H_EVAL".to_string(),
            layout.plinth_expected_h_eval(vk)?,
        );
        data.insert(
            "PLINTH_SHPLONK_PAIRING_CHECK".to_string(),
            layout.plinth_shplonk_pairing_check(),
        );
        data.insert(
            "PLINTH_VANISHING_H_MSM".to_string(),
            layout.plinth_vanishing_h_msm(),
        );

        Ok(Self { data })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ColumnKind {
    Advice,
    Fixed,
    Instance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ColumnQuery {
    kind: ColumnKind,
    column: usize,
    rotation: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PermutationColumn {
    kind: ColumnKind,
    column: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CommitmentRef {
    Advice(usize),
    Fixed(usize),
    PermutationCommon(usize),
    PermutationProduct(usize),
    LookupPermutedInput(usize),
    LookupPermutedTable(usize),
    LookupProduct(usize),
    RandomPoly,
    VanishingH,
}

#[derive(Clone, Debug)]
struct OpeningQuery {
    commitment: CommitmentRef,
    rotation: i32,
    aiken_eval: String,
    plinth_eval: String,
}

#[derive(Clone, Debug)]
struct CommitmentOpening {
    commitment: CommitmentRef,
    evals: Vec<(i32, String, String)>,
}

#[derive(Clone, Debug)]
struct RotationSet {
    points: Vec<i32>,
    commitments: Vec<CommitmentOpening>,
}

struct AxiomLayout {
    num_advice_columns: usize,
    quotient_poly_degree: usize,
    blinding_factors: usize,
    permutation_columns: Vec<PermutationColumn>,
    permutation_set_count: usize,
    lookup_count: usize,
    advice_queries: Vec<ColumnQuery>,
    fixed_queries: Vec<ColumnQuery>,
    query_sets: Vec<RotationSet>,
    super_points: Vec<i32>,
}

impl AxiomLayout {
    fn from_vk(vk: &VerifyingKey<G1Affine>) -> Result<Self> {
        let cs = vk.cs();
        ensure!(
            cs.num_instance_columns() == 0 && cs.instance_queries().is_empty(),
            "Axiom SHPLONK generator does not yet support instance columns"
        );
        ensure!(
            cs.num_challenges() == 0,
            "Axiom SHPLONK generator does not yet support circuit-defined challenges"
        );
        ensure!(
            cs.advice_column_phase().iter().all(|phase| *phase == 0),
            "Axiom SHPLONK generator does not yet support multi-phase advice"
        );

        let permutation_columns = cs
            .permutation()
            .get_columns()
            .into_iter()
            .map(|column| {
                Ok(PermutationColumn {
                    kind: column_kind(column.column_type())?,
                    column: column.index(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let chunk_len = cs.degree().saturating_sub(2);
        ensure!(chunk_len > 0, "invalid Axiom constraint-system degree");
        let permutation_set_count = permutation_columns.chunks(chunk_len).count();
        let advice_queries = cs
            .advice_queries()
            .iter()
            .map(|(column, rotation)| ColumnQuery {
                kind: ColumnKind::Advice,
                column: column.index(),
                rotation: rotation.0,
            })
            .collect::<Vec<_>>();
        let fixed_queries = cs
            .fixed_queries()
            .iter()
            .map(|(column, rotation)| ColumnQuery {
                kind: ColumnKind::Fixed,
                column: column.index(),
                rotation: rotation.0,
            })
            .collect::<Vec<_>>();
        let lookup_count = cs.lookups().len();
        let blinding_factors = cs.blinding_factors();
        let quotient_poly_degree = vk.get_domain().get_quotient_poly_degree();
        let query_sets = shplonk_rotation_sets(
            &advice_queries,
            &fixed_queries,
            &permutation_columns,
            permutation_set_count,
            lookup_count,
            blinding_factors,
        );
        let super_points = query_sets
            .iter()
            .flat_map(|set| set.points.iter().copied())
            .fold(Vec::<i32>::new(), |mut acc, rotation| {
                if !acc.contains(&rotation) {
                    acc.push(rotation);
                }
                acc
            });

        Ok(Self {
            num_advice_columns: cs.num_advice_columns(),
            quotient_poly_degree,
            blinding_factors,
            permutation_columns,
            permutation_set_count,
            lookup_count,
            advice_queries,
            fixed_queries,
            query_sets,
            super_points,
        })
    }

    fn aiken_proof_fields(&self) -> String {
        self.proof_fields("  ", "ByteArray", "State<Scalar>", NameStyle::Aiken)
    }

    fn plinth_proof_fields(&self) -> String {
        self.proof_items()
            .into_iter()
            .enumerate()
            .map(|(idx, item)| {
                let prefix = if idx == 0 { "" } else { "    , " };
                let ty = match item.kind {
                    ProofItemKind::Point => "RawPoint",
                    ProofItemKind::Scalar | ProofItemKind::Challenge => "Scalar",
                };
                format!("{prefix}{} :: {ty}", item.name.plinth())
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn proof_fields(
        &self,
        indent: &str,
        point_type: &str,
        scalar_type: &str,
        style: NameStyle,
    ) -> String {
        self.proof_items()
            .into_iter()
            .map(|item| {
                let ty = match item.kind {
                    ProofItemKind::Point => point_type,
                    ProofItemKind::Scalar | ProofItemKind::Challenge => scalar_type,
                };
                format!("{indent}{}: {ty},", item.name.for_style(style))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn aiken_parse_proof(&self) -> String {
        let mut lines =
            vec!["  let transcript = construct_transcript(proof, transcript_rep)".to_string()];
        for item in self.proof_items() {
            let read = match item.kind {
                ProofItemKind::Point => "read_point",
                ProofItemKind::Scalar => "read_scalar",
                ProofItemKind::Challenge => "squeeze_challenge",
            };
            lines.push(format!(
                "  let ({}, transcript) = {read}(transcript)",
                item.name.aiken()
            ));
        }
        lines.push("  ProofPieces {".to_string());
        lines.extend(
            self.proof_items()
                .into_iter()
                .map(|item| format!("    {},", item.name.aiken())),
        );
        lines.push("  }".to_string());
        lines.join("\n")
    }

    fn plinth_parse_proof(&self) -> String {
        let items = self.proof_items();
        let mut lines = vec![
            "    let !state0 = (proof, commonScalar transcriptRep emptyByteString)".to_string(),
        ];
        for (idx, item) in items.iter().enumerate() {
            let read = match item.kind {
                ProofItemKind::Point => "readRawPoint",
                ProofItemKind::Scalar => "readScalar",
                ProofItemKind::Challenge => "squeezeChallenge",
            };
            lines.push(format!(
                "        (!{}', !state{}) = {read} state{}",
                item.name.plinth(),
                idx + 1,
                idx
            ));
        }
        lines.push("     in ProofPieces".to_string());
        lines.extend(
            items
                .into_iter()
                .map(|item| format!("            {}'", item.name.plinth())),
        );
        lines.join("\n")
    }

    fn aiken_expected_h_eval(&self, vk: &VerifyingKey<G1Affine>) -> Result<String> {
        let mut lines = self.aiken_lagrange_prelude();
        let mut terms = Vec::<String>::new();

        for (idx, expression) in vk
            .cs()
            .gates()
            .iter()
            .flat_map(|gate| gate.polynomials().iter())
            .enumerate()
        {
            let name = format!("gate_{idx}");
            lines.push(format!(
                "  let {name} = {}",
                self.aiken_expression(expression)?
            ));
            terms.push(name);
        }

        self.aiken_permutation_terms(&mut lines, &mut terms)?;
        self.aiken_lookup_terms(vk, &mut lines, &mut terms)?;
        lines.extend(aiken_folded_terms(&terms));
        Ok(lines.join("\n"))
    }

    fn plinth_expected_h_eval(&self, vk: &VerifyingKey<G1Affine>) -> Result<String> {
        let mut lines = self.plinth_lagrange_prelude();
        let mut terms = Vec::<String>::new();

        for (idx, expression) in vk
            .cs()
            .gates()
            .iter()
            .flat_map(|gate| gate.polynomials().iter())
            .enumerate()
        {
            let name = format!("gate{idx}");
            lines.push(format!(
                "        !{name} = {}",
                self.plinth_expression(expression)?
            ));
            terms.push(name);
        }

        self.plinth_permutation_terms(&mut lines, &mut terms)?;
        self.plinth_lookup_terms(vk, &mut lines, &mut terms)?;
        lines.extend(plinth_folded_terms(&terms));
        Ok(lines.join("\n"))
    }

    fn aiken_lagrange_prelude(&self) -> Vec<String> {
        let blind_names = (0..self.blinding_factors)
            .map(|idx| format!("l_blind_{idx}"))
            .collect::<Vec<_>>();
        let mut pattern = vec!["l_last".to_string()];
        pattern.extend(blind_names.iter().cloned());
        pattern.push("l_0".to_string());
        vec![
            "  let scalar_zero = from_int(0)".to_string(),
            "  let scalar_one = from_int(1)".to_string(),
            "  let xn = scalar_pow(p.x, n)".to_string(),
            "  let rotations = rotate_omegas(omega, omega_inv, -(blinding_factors + 1), 0)"
                .to_string(),
            "  let l_evals = lagrange_polynomial_basis(p.x, xn, barycentric_weight, rotations)"
                .to_string(),
            format!("  expect [{}] = l_evals", pattern.join(", ")),
            format!("  let l_blind = {}", aiken_sum(&blind_names)),
            "  let active_rows = sub(scalar_one, add(l_last, l_blind))".to_string(),
        ]
    }

    fn plinth_lagrange_prelude(&self) -> Vec<String> {
        let blind_terms = (1..=self.blinding_factors)
            .map(|idx| format!("(lEvals !! {idx})"))
            .collect::<Vec<_>>();
        vec![
            "    let !xn = powMod (x pieces) n".to_string(),
            "        !rotateOmega = BlsUtils.rotateOmega omega omegaInv".to_string(),
            "        !rotations =".to_string(),
            format!(
                "            [{}]",
                (-(self.blinding_factors as i32 + 1)..=0)
                    .map(|rotation| format!("rotateOmega one {rotation}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "        !lEvals = lagrangePolynomialBasis (x pieces) xn barycentricWeight rotations"
                .to_string(),
            "        !lLast = lEvals !! 0".to_string(),
            format!("        !lBlind = {}", plinth_sum(&blind_terms)),
            format!("        !l0 = lEvals !! {}", self.blinding_factors + 1),
            "        !activeRows = scalarOne - (lLast + lBlind)".to_string(),
        ]
    }

    fn aiken_permutation_terms(
        &self,
        lines: &mut Vec<String>,
        terms: &mut Vec<String>,
    ) -> Result<()> {
        if self.permutation_set_count == 0 {
            return Ok(());
        }
        lines.push(format!(
            "  let perm_first = mul(l_0, sub(scalar_one, {}))",
            aiken_field_access(&permutation_eval_name(0))
        ));
        terms.push("perm_first".to_string());
        let last = self.permutation_set_count - 1;
        lines.push(format!(
            "  let perm_last = mul(l_last, sub(mul({0}, {0}), {0}))",
            aiken_field_access(&permutation_eval_name(last))
        ));
        terms.push("perm_last".to_string());
        for set in 1..self.permutation_set_count {
            let name = format!("perm_link_{set}");
            lines.push(format!(
                "  let {name} = mul(l_0, sub({}, {}))",
                aiken_field_access(&permutation_eval_name(set)),
                aiken_field_access(&permutation_last_name(set - 1))
            ));
            terms.push(name);
        }
        let chunk_len = self.chunk_len();
        for (set, columns) in self.permutation_columns.chunks(chunk_len).enumerate() {
            let name = format!("perm_set_{set}");
            let mut left = vec![aiken_field_access(&permutation_next_name(set))];
            let mut right = vec![aiken_field_access(&permutation_eval_name(set))];
            for (idx, column) in columns.iter().enumerate() {
                let global_idx = set * chunk_len + idx;
                let eval = self.aiken_permutation_column_eval(column)?;
                left.push(aiken_sum(&[
                    eval.clone(),
                    format!(
                        "mul(p.beta, {})",
                        aiken_field_access(&permutation_common_eval_name(global_idx))
                    ),
                    "p.gamma".to_string(),
                ]));
                right.push(aiken_sum(&[
                    eval,
                    aiken_delta_term(global_idx),
                    "p.gamma".to_string(),
                ]));
            }
            lines.push(format!(
                "  let {name} = mul(active_rows, sub({}, {}))",
                aiken_product(&left),
                aiken_product(&right)
            ));
            terms.push(name);
        }
        Ok(())
    }

    fn plinth_permutation_terms(
        &self,
        lines: &mut Vec<String>,
        terms: &mut Vec<String>,
    ) -> Result<()> {
        if self.permutation_set_count == 0 {
            return Ok(());
        }
        lines.push(format!(
            "        !permFirst = l0 * (scalarOne - {})",
            plinth_field_access(&permutation_eval_name(0))
        ));
        terms.push("permFirst".to_string());
        let last = self.permutation_set_count - 1;
        lines.push(format!(
            "        !permLast = lLast * ({0} * {0} - {0})",
            plinth_field_access(&permutation_eval_name(last))
        ));
        terms.push("permLast".to_string());
        for set in 1..self.permutation_set_count {
            let name = format!("permLink{set}");
            lines.push(format!(
                "        !{name} = l0 * ({} - {})",
                plinth_field_access(&permutation_eval_name(set)),
                plinth_field_access(&permutation_last_name(set - 1))
            ));
            terms.push(name);
        }
        let chunk_len = self.chunk_len();
        for (set, columns) in self.permutation_columns.chunks(chunk_len).enumerate() {
            let name = format!("permSet{set}");
            let mut left = vec![plinth_field_access(&permutation_next_name(set))];
            let mut right = vec![plinth_field_access(&permutation_eval_name(set))];
            for (idx, column) in columns.iter().enumerate() {
                let global_idx = set * chunk_len + idx;
                let eval = self.plinth_permutation_column_eval(column)?;
                left.push(plinth_sum(&[
                    eval.clone(),
                    format!(
                        "beta pieces * {}",
                        plinth_field_access(&permutation_common_eval_name(global_idx))
                    ),
                    "gamma pieces".to_string(),
                ]));
                right.push(plinth_sum(&[
                    eval,
                    plinth_delta_term(global_idx),
                    "gamma pieces".to_string(),
                ]));
            }
            lines.push(format!(
                "        !{name} = activeRows * ({} - {})",
                plinth_product(&left),
                plinth_product(&right)
            ));
            terms.push(name);
        }
        Ok(())
    }

    fn aiken_lookup_terms(
        &self,
        vk: &VerifyingKey<G1Affine>,
        lines: &mut Vec<String>,
        terms: &mut Vec<String>,
    ) -> Result<()> {
        for (idx, lookup) in vk.cs().lookups().iter().enumerate() {
            let compressed_input = self.aiken_compressed_lookup(lookup.input_expressions())?;
            let compressed_table = self.aiken_compressed_lookup(lookup.table_expressions())?;
            let product = aiken_field_access(&lookup_product_eval_name(idx));
            let product_next = aiken_field_access(&lookup_product_next_name(idx));
            let input = aiken_field_access(&lookup_input_eval_name(idx));
            let input_prev = aiken_field_access(&lookup_input_prev_eval_name(idx));
            let table = aiken_field_access(&lookup_table_eval_name(idx));

            let first = format!("lookup_{idx}_first");
            lines.push(format!(
                "  let {first} = mul(l_0, sub(scalar_one, {product}))"
            ));
            terms.push(first);
            let last = format!("lookup_{idx}_last");
            lines.push(format!(
                "  let {last} = mul(l_last, sub(mul({product}, {product}), {product}))"
            ));
            terms.push(last);
            let product_expr = format!("lookup_{idx}_product_expression");
            lines.push(format!(
                "  let {product_expr} = mul(active_rows, sub(mul(mul({product_next}, add({input}, p.beta)), add({table}, p.gamma)), mul(mul({product}, add({compressed_input}, p.beta)), add({compressed_table}, p.gamma))))"
            ));
            terms.push(product_expr);
            let initial = format!("lookup_{idx}_initial");
            lines.push(format!("  let {initial} = mul(l_0, sub({input}, {table}))"));
            terms.push(initial);
            let adjacent = format!("lookup_{idx}_adjacent");
            lines.push(format!(
                "  let {adjacent} = mul(mul(active_rows, sub({input}, {table})), sub({input}, {input_prev}))"
            ));
            terms.push(adjacent);
        }
        Ok(())
    }

    fn plinth_lookup_terms(
        &self,
        vk: &VerifyingKey<G1Affine>,
        lines: &mut Vec<String>,
        terms: &mut Vec<String>,
    ) -> Result<()> {
        for (idx, lookup) in vk.cs().lookups().iter().enumerate() {
            let compressed_input = self.plinth_compressed_lookup(lookup.input_expressions())?;
            let compressed_table = self.plinth_compressed_lookup(lookup.table_expressions())?;
            let product = plinth_field_access(&lookup_product_eval_name(idx));
            let product_next = plinth_field_access(&lookup_product_next_name(idx));
            let input = plinth_field_access(&lookup_input_eval_name(idx));
            let input_prev = plinth_field_access(&lookup_input_prev_eval_name(idx));
            let table = plinth_field_access(&lookup_table_eval_name(idx));

            let first = format!("lookup{idx}First");
            lines.push(format!("        !{first} = l0 * (scalarOne - {product})"));
            terms.push(first);
            let last = format!("lookup{idx}Last");
            lines.push(format!(
                "        !{last} = lLast * ({product} * {product} - {product})"
            ));
            terms.push(last);
            let product_expr = format!("lookup{idx}ProductExpression");
            lines.push(format!(
                "        !{product_expr} = activeRows * ({product_next} * ({input} + beta pieces) * ({table} + gamma pieces) - {product} * ({compressed_input} + beta pieces) * ({compressed_table} + gamma pieces))"
            ));
            terms.push(product_expr);
            let initial = format!("lookup{idx}Initial");
            lines.push(format!("        !{initial} = l0 * ({input} - {table})"));
            terms.push(initial);
            let adjacent = format!("lookup{idx}Adjacent");
            lines.push(format!(
                "        !{adjacent} = activeRows * ({input} - {table}) * ({input} - {input_prev})"
            ));
            terms.push(adjacent);
        }
        Ok(())
    }

    fn aiken_shplonk_pairing_check(&self) -> String {
        let mut lines = Vec::<String>::new();
        lines.push("  let xn = scalar_pow(p.x, n)".to_string());
        lines.extend(
            self.super_points
                .iter()
                .map(|rotation| aiken_rotation_binding(*rotation)),
        );
        let first_points = self.query_sets[0].points.clone();
        let first_complement = complement_rotations(&self.super_points, &first_points);
        lines.push(format!(
            "  let z0 = vanishing({}, p.u)",
            aiken_rotation_list(&first_points)
        ));
        lines.push(format!(
            "  let z0_diff_inv = recip_eea(vanishing({}, p.u))",
            aiken_rotation_list(&first_complement)
        ));
        for (idx, set) in self.query_sets.iter().enumerate() {
            let z_diff = if idx == 0 {
                "from_int(1)".to_string()
            } else {
                format!(
                    "mul(vanishing({}, p.u), z0_diff_inv)",
                    aiken_rotation_list(&complement_rotations(&self.super_points, &set.points))
                )
            };
            lines.push(format!(
                "  let (msm_{idx}, r_{idx}) =\n    rotation_contribution(\n      {},\n      {},\n      p.u,\n      p.shplonk_y,\n      {},\n      {},\n    )",
                aiken_rotation_list(&set.points),
                self.aiken_openings_list(set),
                aiken_power("p.v", idx),
                z_diff
            ));
        }
        let msm_names = (0..self.query_sets.len())
            .map(|idx| format!("msm_{idx}"))
            .collect::<Vec<_>>();
        let r_names = (0..self.query_sets.len())
            .map(|idx| format!("r_{idx}"))
            .collect::<Vec<_>>();
        lines.push(format!(
            "  let outer_msm =\n    foldl([{}], MSM {{ elements: [] }}, fn(msm, acc) {{ add_msm(acc, msm) }})",
            msm_names.join(", ")
        ));
        lines.push(format!(
            "  let r_outer =\n    foldl([{}], from_int(0), fn(r, acc) {{ add(acc, r) }})",
            r_names.join(", ")
        ));
        lines.push(
            "  let outer_msm =\n    add_msm(\n      outer_msm,\n      MSM {\n        elements: [\n          MSMElement { scalar: neg(r_outer), g1: g1_generator_bytes },\n          MSMElement { scalar: neg(z0), g1: p.shplonk_h1 },\n          MSMElement { scalar: p.u, g1: p.shplonk_h2 },\n        ],\n      },\n    )".to_string(),
        );
        lines.push(
            "  final_exponentiation(\n    miller_loop(axiom_decompress_g1(p.shplonk_h2), s_g2),\n    miller_loop(eval_axiom_msm(outer_msm), generator_g2),\n  )".to_string(),
        );
        lines.join("\n")
    }

    fn plinth_shplonk_pairing_check(&self) -> String {
        let mut lines = Vec::<String>::new();
        lines.push("    let !rotateOmega = BlsUtils.rotateOmega omega omegaInv".to_string());
        lines.extend(
            self.super_points
                .iter()
                .map(|rotation| plinth_rotation_binding(*rotation)),
        );
        lines.push("        !xn = powMod (x pieces) n".to_string());
        let first_points = self.query_sets[0].points.clone();
        let first_complement = complement_rotations(&self.super_points, &first_points);
        lines.push(format!(
            "        !z0 = vanishing {} (u pieces)",
            plinth_rotation_list(&first_points)
        ));
        lines.push(format!(
            "        !z0DiffInv = recip (vanishing {} (u pieces))",
            plinth_rotation_list(&first_complement)
        ));
        for (idx, set) in self.query_sets.iter().enumerate() {
            let z_diff = if idx == 0 {
                "scalarOne".to_string()
            } else {
                format!(
                    "vanishing {} (u pieces) * z0DiffInv",
                    plinth_rotation_list(&complement_rotations(&self.super_points, &set.points))
                )
            };
            lines.push(format!(
                "        (!msm{idx}, !r{idx}) =\n            rotationContribution\n                {}\n                {}\n                (u pieces)\n                (shplonkY pieces)\n                {}\n                ({})",
                plinth_rotation_list(&set.points),
                self.plinth_openings_list(set),
                plinth_power("v pieces", idx),
                z_diff
            ));
        }
        let msm_names = (0..self.query_sets.len())
            .map(|idx| format!("msm{idx}"))
            .collect::<Vec<_>>();
        let r_names = (0..self.query_sets.len())
            .map(|idx| format!("r{idx}"))
            .collect::<Vec<_>>();
        lines.push(format!(
            "        !outerMsm = foldl addRawMsm (RawMSM []) [{}]",
            msm_names.join(", ")
        ));
        lines.push(format!(
            "        !rOuter = foldl (+) scalarZero [{}]",
            r_names.join(", ")
        ));
        lines.push(
            "        !outerMsm' =\n            addRawMsm\n                outerMsm\n                ( RawMSM\n                    [ RawMSMElement (negate rOuter) g1GeneratorBytes\n                    , RawMSMElement (negate z0) (shplonkH1 pieces)\n                    , RawMSMElement (u pieces) (shplonkH2 pieces)\n                    ]\n                )\n        !g2 = bls12_381_G2_uncompress bls12_381_G2_compressed_generator\n        !mlLeft = bls12_381_millerLoop (axiomDecompressG1 (shplonkH2 pieces)) sG2\n        !mlRight = bls12_381_millerLoop (evalAxiomMsm outerMsm') g2\n     in bls12_381_finalVerify mlLeft mlRight".to_string(),
        );
        lines.join("\n")
    }

    fn aiken_openings_list(&self, set: &RotationSet) -> String {
        format!(
            "[\n{}\n      ]",
            set.commitments
                .iter()
                .map(|opening| format!("        {},", self.aiken_opening(opening)))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    fn plinth_openings_list(&self, set: &RotationSet) -> String {
        format!(
            "[{}]",
            set.commitments
                .iter()
                .map(|opening| self.plinth_opening(opening))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    fn aiken_opening(&self, opening: &CommitmentOpening) -> String {
        let evals = opening
            .evals
            .iter()
            .map(|(_, aiken, _)| aiken.clone())
            .collect::<Vec<_>>();
        match opening.commitment {
            CommitmentRef::VanishingH => {
                format!(
                    "Opening {{ msm: vanishing_h_msm(p, xn), evals: [{}] }}",
                    evals.join(", ")
                )
            }
            _ => format!(
                "point_opening({}, [{}])",
                aiken_commitment_ref(&opening.commitment),
                evals.join(", ")
            ),
        }
    }

    fn plinth_opening(&self, opening: &CommitmentOpening) -> String {
        let evals = opening
            .evals
            .iter()
            .map(|(_, _, plinth)| plinth.clone())
            .collect::<Vec<_>>();
        match opening.commitment {
            CommitmentRef::VanishingH => {
                format!("Opening (vanishingHMsm pieces xn) [{}]", evals.join(", "))
            }
            _ => format!(
                "pointOpening {} [{}]",
                plinth_commitment_ref(&opening.commitment),
                evals.join(", ")
            ),
        }
    }

    fn aiken_vanishing_h_msm(&self) -> String {
        let elements = (0..self.quotient_poly_degree)
            .map(|idx| {
                format!(
                    "      MSMElement {{ scalar: {}, g1: p.{} }},",
                    aiken_xn_power(idx),
                    h_commitment_name(idx).aiken()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!("  MSM {{\n    elements: [\n{elements}\n    ],\n  }}")
    }

    fn plinth_vanishing_h_msm(&self) -> String {
        let elements = (0..self.quotient_poly_degree)
            .map(|idx| {
                format!(
                    "        RawMSMElement {} ({} pieces)",
                    plinth_xn_power(idx),
                    h_commitment_name(idx).plinth()
                )
            })
            .collect::<Vec<_>>()
            .join("\n        , ");
        format!("    RawMSM\n        [ {elements}\n        ]")
    }

    fn proof_items(&self) -> Vec<ProofItem> {
        let mut items = Vec::new();
        for idx in 0..self.num_advice_columns {
            items.push(ProofItem::point(advice_commitment_name(idx)));
        }
        items.push(ProofItem::challenge(Name::new("theta")));
        for idx in 0..self.lookup_count {
            items.push(ProofItem::point(lookup_permuted_input_name(idx)));
            items.push(ProofItem::point(lookup_permuted_table_name(idx)));
        }
        items.push(ProofItem::challenge(Name::new("beta")));
        items.push(ProofItem::challenge(Name::new("gamma")));
        for idx in 0..self.permutation_set_count {
            items.push(ProofItem::point(permutation_product_name(idx)));
        }
        for idx in 0..self.lookup_count {
            items.push(ProofItem::point(lookup_product_name(idx)));
        }
        items.push(ProofItem::point(Name::new("random_poly")));
        items.push(ProofItem::challenge(Name::new("plonk_y")));
        for idx in 0..self.quotient_poly_degree {
            items.push(ProofItem::point(h_commitment_name(idx)));
        }
        items.push(ProofItem::challenge(Name::new("x")));
        for idx in 0..self.advice_queries.len() {
            items.push(ProofItem::scalar(advice_eval_name(idx)));
        }
        for idx in 0..self.fixed_queries.len() {
            items.push(ProofItem::scalar(fixed_eval_name(idx)));
        }
        items.push(ProofItem::scalar(Name::new("random_eval")));
        for idx in 0..self.permutation_columns.len() {
            items.push(ProofItem::scalar(permutation_common_eval_name(idx)));
        }
        for idx in 0..self.permutation_set_count {
            items.push(ProofItem::scalar(permutation_eval_name(idx)));
            items.push(ProofItem::scalar(permutation_next_name(idx)));
            if idx + 1 < self.permutation_set_count {
                items.push(ProofItem::scalar(permutation_last_name(idx)));
            }
        }
        for idx in 0..self.lookup_count {
            items.push(ProofItem::scalar(lookup_product_eval_name(idx)));
            items.push(ProofItem::scalar(lookup_product_next_name(idx)));
            items.push(ProofItem::scalar(lookup_input_eval_name(idx)));
            items.push(ProofItem::scalar(lookup_input_prev_eval_name(idx)));
            items.push(ProofItem::scalar(lookup_table_eval_name(idx)));
        }
        items.push(ProofItem::challenge(Name::new("shplonk_y")));
        items.push(ProofItem::challenge(Name::new("v")));
        items.push(ProofItem::point(Name::new("shplonk_h1")));
        items.push(ProofItem::challenge(Name::new("u")));
        items.push(ProofItem::point(Name::new("shplonk_h2")));
        items
    }

    fn aiken_expression(&self, expression: &Expression<BlsFr>) -> Result<String> {
        match expression {
            Expression::Constant(scalar) => Ok(aiken_scalar_literal(*scalar)),
            Expression::Selector(_) => bail!("Axiom selector expressions are not supported"),
            Expression::Fixed(query) => {
                let idx = self.fixed_query_index(query.column_index(), query.rotation().0)?;
                Ok(aiken_field_access(&fixed_eval_name(idx)))
            }
            Expression::Advice(query) => {
                let idx = self.advice_query_index(query.column_index(), query.rotation().0)?;
                Ok(aiken_field_access(&advice_eval_name(idx)))
            }
            Expression::Instance(_) => bail!("Axiom instance expressions are not supported"),
            Expression::Challenge(_) => {
                bail!("Axiom circuit challenge expressions are not supported")
            }
            Expression::Negated(a) => Ok(format!("neg({})", self.aiken_expression(a)?)),
            Expression::Sum(a, b) => Ok(format!(
                "add({}, {})",
                self.aiken_expression(a)?,
                self.aiken_expression(b)?
            )),
            Expression::Product(a, b) => Ok(format!(
                "mul({}, {})",
                self.aiken_expression(a)?,
                self.aiken_expression(b)?
            )),
            Expression::Scaled(a, scalar) => Ok(format!(
                "mul({}, {})",
                self.aiken_expression(a)?,
                aiken_scalar_literal(*scalar)
            )),
        }
    }

    fn plinth_expression(&self, expression: &Expression<BlsFr>) -> Result<String> {
        match expression {
            Expression::Constant(scalar) => Ok(plinth_scalar_literal(*scalar)),
            Expression::Selector(_) => bail!("Axiom selector expressions are not supported"),
            Expression::Fixed(query) => {
                let idx = self.fixed_query_index(query.column_index(), query.rotation().0)?;
                Ok(plinth_field_access(&fixed_eval_name(idx)))
            }
            Expression::Advice(query) => {
                let idx = self.advice_query_index(query.column_index(), query.rotation().0)?;
                Ok(plinth_field_access(&advice_eval_name(idx)))
            }
            Expression::Instance(_) => bail!("Axiom instance expressions are not supported"),
            Expression::Challenge(_) => {
                bail!("Axiom circuit challenge expressions are not supported")
            }
            Expression::Negated(a) => Ok(format!("negate ({})", self.plinth_expression(a)?)),
            Expression::Sum(a, b) => Ok(format!(
                "({} + {})",
                self.plinth_expression(a)?,
                self.plinth_expression(b)?
            )),
            Expression::Product(a, b) => Ok(format!(
                "({} * {})",
                self.plinth_expression(a)?,
                self.plinth_expression(b)?
            )),
            Expression::Scaled(a, scalar) => Ok(format!(
                "({} * {})",
                self.plinth_expression(a)?,
                plinth_scalar_literal(*scalar)
            )),
        }
    }

    fn aiken_compressed_lookup(&self, expressions: &[Expression<BlsFr>]) -> Result<String> {
        let compiled = expressions
            .iter()
            .map(|expression| self.aiken_expression(expression))
            .collect::<Result<Vec<_>>>()?;
        Ok(match compiled.as_slice() {
            [] => "from_int(0)".to_string(),
            [single] => single.clone(),
            _ => format!(
                "foldl([{}], from_int(0), fn(expr, acc) {{ add(mul(acc, p.theta), expr) }})",
                compiled.join(", ")
            ),
        })
    }

    fn plinth_compressed_lookup(&self, expressions: &[Expression<BlsFr>]) -> Result<String> {
        let compiled = expressions
            .iter()
            .map(|expression| self.plinth_expression(expression))
            .collect::<Result<Vec<_>>>()?;
        Ok(match compiled.as_slice() {
            [] => "scalarZero".to_string(),
            [single] => single.clone(),
            _ => format!(
                "foldl (\\acc expr -> acc * theta pieces + expr) scalarZero [{}]",
                compiled.join(", ")
            ),
        })
    }

    fn aiken_permutation_column_eval(&self, column: &PermutationColumn) -> Result<String> {
        match column.kind {
            ColumnKind::Advice => {
                let idx = self.advice_query_index(column.column, 0)?;
                Ok(aiken_field_access(&advice_eval_name(idx)))
            }
            ColumnKind::Fixed => {
                let idx = self.fixed_query_index(column.column, 0)?;
                Ok(aiken_field_access(&fixed_eval_name(idx)))
            }
            ColumnKind::Instance => bail!("Axiom instance permutation columns are not supported"),
        }
    }

    fn plinth_permutation_column_eval(&self, column: &PermutationColumn) -> Result<String> {
        match column.kind {
            ColumnKind::Advice => {
                let idx = self.advice_query_index(column.column, 0)?;
                Ok(plinth_field_access(&advice_eval_name(idx)))
            }
            ColumnKind::Fixed => {
                let idx = self.fixed_query_index(column.column, 0)?;
                Ok(plinth_field_access(&fixed_eval_name(idx)))
            }
            ColumnKind::Instance => bail!("Axiom instance permutation columns are not supported"),
        }
    }

    fn advice_query_index(&self, column: usize, rotation: i32) -> Result<usize> {
        self.query_index(&self.advice_queries, column, rotation)
            .with_context(|| {
                format!("missing advice query for column {column} at rotation {rotation}")
            })
    }

    fn fixed_query_index(&self, column: usize, rotation: i32) -> Result<usize> {
        self.query_index(&self.fixed_queries, column, rotation)
            .with_context(|| {
                format!("missing fixed query for column {column} at rotation {rotation}")
            })
    }

    fn query_index(&self, queries: &[ColumnQuery], column: usize, rotation: i32) -> Result<usize> {
        queries
            .iter()
            .position(|query| query.column == column && query.rotation == rotation)
            .context("query not found")
    }

    fn chunk_len(&self) -> usize {
        if self.permutation_set_count == 0 {
            self.permutation_columns.len().max(1)
        } else {
            self.permutation_columns
                .len()
                .div_ceil(self.permutation_set_count)
        }
    }
}

#[derive(Clone, Copy)]
enum NameStyle {
    Aiken,
    Plinth,
}

#[derive(Clone)]
struct Name {
    snake: String,
}

impl Name {
    fn new(snake: impl Into<String>) -> Self {
        Self {
            snake: snake.into(),
        }
    }

    fn aiken(&self) -> String {
        self.snake.clone()
    }

    fn plinth(&self) -> String {
        snake_to_lower_camel(&self.snake)
    }

    fn for_style(&self, style: NameStyle) -> String {
        match style {
            NameStyle::Aiken => self.aiken(),
            NameStyle::Plinth => self.plinth(),
        }
    }
}

struct ProofItem {
    name: Name,
    kind: ProofItemKind,
}

impl ProofItem {
    fn point(name: Name) -> Self {
        Self {
            name,
            kind: ProofItemKind::Point,
        }
    }

    fn scalar(name: Name) -> Self {
        Self {
            name,
            kind: ProofItemKind::Scalar,
        }
    }

    fn challenge(name: Name) -> Self {
        Self {
            name,
            kind: ProofItemKind::Challenge,
        }
    }
}

#[derive(Clone, Copy)]
enum ProofItemKind {
    Point,
    Scalar,
    Challenge,
}

fn shplonk_rotation_sets(
    advice_queries: &[ColumnQuery],
    fixed_queries: &[ColumnQuery],
    permutation_columns: &[PermutationColumn],
    permutation_set_count: usize,
    lookup_count: usize,
    blinding_factors: usize,
) -> Vec<RotationSet> {
    let mut queries = Vec::<OpeningQuery>::new();
    queries.extend(
        advice_queries
            .iter()
            .enumerate()
            .map(|(idx, query)| OpeningQuery {
                commitment: CommitmentRef::Advice(query.column),
                rotation: query.rotation,
                aiken_eval: aiken_field_access(&advice_eval_name(idx)),
                plinth_eval: plinth_field_access(&advice_eval_name(idx)),
            }),
    );
    let last_rotation = -((blinding_factors + 1) as i32);
    for set in 0..permutation_set_count {
        queries.push(OpeningQuery {
            commitment: CommitmentRef::PermutationProduct(set),
            rotation: 0,
            aiken_eval: aiken_field_access(&permutation_eval_name(set)),
            plinth_eval: plinth_field_access(&permutation_eval_name(set)),
        });
        queries.push(OpeningQuery {
            commitment: CommitmentRef::PermutationProduct(set),
            rotation: 1,
            aiken_eval: aiken_field_access(&permutation_next_name(set)),
            plinth_eval: plinth_field_access(&permutation_next_name(set)),
        });
    }
    for set in (0..permutation_set_count.saturating_sub(1)).rev() {
        queries.push(OpeningQuery {
            commitment: CommitmentRef::PermutationProduct(set),
            rotation: last_rotation,
            aiken_eval: aiken_field_access(&permutation_last_name(set)),
            plinth_eval: plinth_field_access(&permutation_last_name(set)),
        });
    }
    for lookup in 0..lookup_count {
        queries.push(OpeningQuery {
            commitment: CommitmentRef::LookupProduct(lookup),
            rotation: 0,
            aiken_eval: aiken_field_access(&lookup_product_eval_name(lookup)),
            plinth_eval: plinth_field_access(&lookup_product_eval_name(lookup)),
        });
        queries.push(OpeningQuery {
            commitment: CommitmentRef::LookupPermutedInput(lookup),
            rotation: 0,
            aiken_eval: aiken_field_access(&lookup_input_eval_name(lookup)),
            plinth_eval: plinth_field_access(&lookup_input_eval_name(lookup)),
        });
        queries.push(OpeningQuery {
            commitment: CommitmentRef::LookupPermutedTable(lookup),
            rotation: 0,
            aiken_eval: aiken_field_access(&lookup_table_eval_name(lookup)),
            plinth_eval: plinth_field_access(&lookup_table_eval_name(lookup)),
        });
        queries.push(OpeningQuery {
            commitment: CommitmentRef::LookupPermutedInput(lookup),
            rotation: -1,
            aiken_eval: aiken_field_access(&lookup_input_prev_eval_name(lookup)),
            plinth_eval: plinth_field_access(&lookup_input_prev_eval_name(lookup)),
        });
        queries.push(OpeningQuery {
            commitment: CommitmentRef::LookupProduct(lookup),
            rotation: 1,
            aiken_eval: aiken_field_access(&lookup_product_next_name(lookup)),
            plinth_eval: plinth_field_access(&lookup_product_next_name(lookup)),
        });
    }
    queries.extend(
        fixed_queries
            .iter()
            .enumerate()
            .map(|(idx, query)| OpeningQuery {
                commitment: CommitmentRef::Fixed(query.column),
                rotation: query.rotation,
                aiken_eval: aiken_field_access(&fixed_eval_name(idx)),
                plinth_eval: plinth_field_access(&fixed_eval_name(idx)),
            }),
    );
    queries.extend(
        permutation_columns
            .iter()
            .enumerate()
            .map(|(idx, _)| OpeningQuery {
                commitment: CommitmentRef::PermutationCommon(idx),
                rotation: 0,
                aiken_eval: aiken_field_access(&permutation_common_eval_name(idx)),
                plinth_eval: plinth_field_access(&permutation_common_eval_name(idx)),
            }),
    );
    queries.push(OpeningQuery {
        commitment: CommitmentRef::VanishingH,
        rotation: 0,
        aiken_eval: "expected_h".to_string(),
        plinth_eval: "expectedH".to_string(),
    });
    queries.push(OpeningQuery {
        commitment: CommitmentRef::RandomPoly,
        rotation: 0,
        aiken_eval: aiken_field_access(&Name::new("random_eval")),
        plinth_eval: plinth_field_access(&Name::new("random_eval")),
    });

    let mut by_commitment = Vec::<(CommitmentRef, Vec<OpeningQuery>)>::new();
    for query in queries {
        if let Some((_, commitment_queries)) = by_commitment
            .iter_mut()
            .find(|(commitment, _)| *commitment == query.commitment)
        {
            commitment_queries.push(query);
        } else {
            by_commitment.push((query.commitment.clone(), vec![query]));
        }
    }

    let mut sets = Vec::<RotationSet>::new();
    for (commitment, commitment_queries) in by_commitment {
        let key = commitment_queries
            .iter()
            .map(|query| query.rotation)
            .collect::<BTreeSet<_>>();
        let points = key.iter().copied().collect::<Vec<_>>();
        let opening = CommitmentOpening {
            commitment,
            evals: points
                .iter()
                .map(|rotation| {
                    let query = commitment_queries
                        .iter()
                        .find(|query| query.rotation == *rotation)
                        .expect("rotation set key came from queries");
                    (
                        *rotation,
                        query.aiken_eval.clone(),
                        query.plinth_eval.clone(),
                    )
                })
                .collect(),
        };
        if let Some(set) = sets
            .iter_mut()
            .find(|set| set.points.iter().copied().collect::<BTreeSet<_>>() == key)
        {
            set.commitments.push(opening);
        } else {
            sets.push(RotationSet {
                points,
                commitments: vec![opening],
            });
        }
    }
    sets
}

fn aiken_fixed_commitments(commitments: &[String]) -> String {
    commitments
        .iter()
        .enumerate()
        .map(|(idx, commitment)| format!("const fixed_{idx} =\n  #\"{commitment}\""))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn aiken_permutation_commitments(commitments: &[String]) -> String {
    commitments
        .iter()
        .enumerate()
        .map(|(idx, commitment)| format!("const permutation_common_{idx} =\n  #\"{commitment}\""))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn plinth_fixed_commitments(commitments: &[String]) -> String {
    commitments
        .iter()
        .enumerate()
        .map(|(idx, commitment)| {
            format!(
                "fixed{idx} :: RawPoint\nfixed{idx} = stringToBuiltinByteStringHex \"{commitment}\""
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn plinth_permutation_commitments(commitments: &[String]) -> String {
    commitments
        .iter()
        .enumerate()
        .map(|(idx, commitment)| {
            format!(
                "permutationCommon{idx} :: RawPoint\npermutationCommon{idx} = stringToBuiltinByteStringHex \"{commitment}\""
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn aiken_folded_terms(terms: &[String]) -> Vec<String> {
    vec![
        "  let folded =".to_string(),
        "    foldl(".to_string(),
        format!("      [{}],", terms.join(", ")),
        "      scalar_zero,".to_string(),
        "      fn(expr, acc) { add(mul(acc, p.plonk_y), expr) },".to_string(),
        "    )".to_string(),
        "  mul(folded, recip_eea(sub_int(xn, 1)))".to_string(),
    ]
}

fn plinth_folded_terms(terms: &[String]) -> Vec<String> {
    vec![
        "        !folded =".to_string(),
        "            foldl".to_string(),
        "                (\\acc expr -> acc * plonkY pieces + expr)".to_string(),
        "                scalarZero".to_string(),
        format!("                [{}]", terms.join(", ")),
        "     in folded * recip (xn - scalarOne)".to_string(),
    ]
}

fn aiken_rotation_binding(rotation: i32) -> String {
    if rotation == 0 {
        "  let x_current = p.x".to_string()
    } else {
        format!(
            "  let {} = rotate_omega(omega, omega_inv, p.x, {rotation})",
            rotation_var(rotation, NameStyle::Aiken)
        )
    }
}

fn plinth_rotation_binding(rotation: i32) -> String {
    if rotation == 0 {
        "        !xCurrent = x pieces".to_string()
    } else {
        format!(
            "        !{} = rotateOmega (x pieces) {rotation}",
            rotation_var(rotation, NameStyle::Plinth)
        )
    }
}

fn aiken_rotation_list(rotations: &[i32]) -> String {
    format!(
        "[{}]",
        rotations
            .iter()
            .map(|rotation| rotation_var(*rotation, NameStyle::Aiken))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn plinth_rotation_list(rotations: &[i32]) -> String {
    format!(
        "[{}]",
        rotations
            .iter()
            .map(|rotation| rotation_var(*rotation, NameStyle::Plinth))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn rotation_var(rotation: i32, style: NameStyle) -> String {
    let snake = if rotation == 0 {
        "x_current".to_string()
    } else if rotation > 0 {
        format!("x_rot_{rotation}")
    } else {
        format!("x_rot_neg_{}", rotation.abs())
    };
    Name::new(snake).for_style(style)
}

fn complement_rotations(super_points: &[i32], points: &[i32]) -> Vec<i32> {
    super_points
        .iter()
        .copied()
        .filter(|point| !points.contains(point))
        .collect()
}

fn aiken_commitment_ref(commitment: &CommitmentRef) -> String {
    match commitment {
        CommitmentRef::Advice(idx) => aiken_field_access(&advice_commitment_name(*idx)),
        CommitmentRef::Fixed(idx) => format!("fixed_{idx}"),
        CommitmentRef::PermutationCommon(idx) => format!("permutation_common_{idx}"),
        CommitmentRef::PermutationProduct(idx) => {
            aiken_field_access(&permutation_product_name(*idx))
        }
        CommitmentRef::LookupPermutedInput(idx) => {
            aiken_field_access(&lookup_permuted_input_name(*idx))
        }
        CommitmentRef::LookupPermutedTable(idx) => {
            aiken_field_access(&lookup_permuted_table_name(*idx))
        }
        CommitmentRef::LookupProduct(idx) => aiken_field_access(&lookup_product_name(*idx)),
        CommitmentRef::RandomPoly => aiken_field_access(&Name::new("random_poly")),
        CommitmentRef::VanishingH => unreachable!("vanishing H is an MSM opening"),
    }
}

fn plinth_commitment_ref(commitment: &CommitmentRef) -> String {
    match commitment {
        CommitmentRef::Advice(idx) => plinth_field_access(&advice_commitment_name(*idx)),
        CommitmentRef::Fixed(idx) => format!("fixed{idx}"),
        CommitmentRef::PermutationCommon(idx) => format!("permutationCommon{idx}"),
        CommitmentRef::PermutationProduct(idx) => {
            plinth_field_access(&permutation_product_name(*idx))
        }
        CommitmentRef::LookupPermutedInput(idx) => {
            plinth_field_access(&lookup_permuted_input_name(*idx))
        }
        CommitmentRef::LookupPermutedTable(idx) => {
            plinth_field_access(&lookup_permuted_table_name(*idx))
        }
        CommitmentRef::LookupProduct(idx) => plinth_field_access(&lookup_product_name(*idx)),
        CommitmentRef::RandomPoly => plinth_field_access(&Name::new("random_poly")),
        CommitmentRef::VanishingH => unreachable!("vanishing H is an MSM opening"),
    }
}

fn aiken_sum(terms: &[String]) -> String {
    match terms {
        [] => "from_int(0)".to_string(),
        [single] => single.clone(),
        [first, rest @ ..] => rest
            .iter()
            .fold(first.clone(), |acc, term| format!("add({acc}, {term})")),
    }
}

fn aiken_product(terms: &[String]) -> String {
    match terms {
        [] => "from_int(1)".to_string(),
        [single] => single.clone(),
        [first, rest @ ..] => rest
            .iter()
            .fold(first.clone(), |acc, term| format!("mul({acc}, {term})")),
    }
}

fn plinth_sum(terms: &[String]) -> String {
    match terms {
        [] => "scalarZero".to_string(),
        [single] => single.clone(),
        [first, rest @ ..] => rest
            .iter()
            .fold(first.clone(), |acc, term| format!("({acc} + {term})")),
    }
}

fn plinth_product(terms: &[String]) -> String {
    match terms {
        [] => "scalarOne".to_string(),
        [single] => single.clone(),
        [first, rest @ ..] => rest
            .iter()
            .fold(first.clone(), |acc, term| format!("({acc} * {term})")),
    }
}

fn aiken_power(base: &str, exponent: usize) -> String {
    match exponent {
        0 => "from_int(1)".to_string(),
        1 => base.to_string(),
        _ => format!("scalar_pow({base}, {exponent})"),
    }
}

fn plinth_power(base: &str, exponent: usize) -> String {
    match exponent {
        0 => "scalarOne".to_string(),
        1 => base.to_string(),
        _ => format!("powMod ({base}) {exponent}"),
    }
}

fn aiken_delta_term(exponent: usize) -> String {
    let beta_x = "mul(p.beta, p.x)";
    match exponent {
        0 => beta_x.to_string(),
        1 => format!("mul({beta_x}, scalar_delta)"),
        _ => format!("mul({beta_x}, scalar_pow(scalar_delta, {exponent}))"),
    }
}

fn plinth_delta_term(exponent: usize) -> String {
    let beta_x = "beta pieces * x pieces";
    match exponent {
        0 => beta_x.to_string(),
        1 => format!("{beta_x} * scalarDelta"),
        _ => format!("{beta_x} * powMod scalarDelta {exponent}"),
    }
}

fn aiken_xn_power(exponent: usize) -> String {
    match exponent {
        0 => "from_int(1)".to_string(),
        1 => "xn".to_string(),
        _ => format!("scalar_pow(xn, {exponent})"),
    }
}

fn plinth_xn_power(exponent: usize) -> String {
    match exponent {
        0 => "scalarOne".to_string(),
        1 => "xn".to_string(),
        _ => format!("powMod xn {exponent}"),
    }
}

fn aiken_field_access(name: &Name) -> String {
    format!("p.{}", name.aiken())
}

fn plinth_field_access(name: &Name) -> String {
    format!("{} pieces", name.plinth())
}

fn aiken_scalar_literal(scalar: BlsFr) -> String {
    format!("from_bytes_little_endian(#\"{}\")", scalar_hex(scalar))
}

fn plinth_scalar_literal(scalar: BlsFr) -> String {
    format!(
        "scalarFromLittleEndianHex (stringToBuiltinByteStringHex \"{}\")",
        scalar_hex(scalar)
    )
}

fn advice_commitment_name(idx: usize) -> Name {
    Name::new(format!("advice_{idx}"))
}

fn advice_eval_name(idx: usize) -> Name {
    Name::new(format!("advice_eval_{idx}"))
}

fn fixed_eval_name(idx: usize) -> Name {
    Name::new(format!("fixed_eval_{idx}"))
}

fn permutation_common_eval_name(idx: usize) -> Name {
    Name::new(format!("permutation_common_eval_{idx}"))
}

fn permutation_product_name(idx: usize) -> Name {
    Name::new(format!("permutation_product_{idx}"))
}

fn permutation_eval_name(idx: usize) -> Name {
    Name::new(format!("permutation_eval_{idx}"))
}

fn permutation_next_name(idx: usize) -> Name {
    Name::new(format!("permutation_next_{idx}"))
}

fn permutation_last_name(idx: usize) -> Name {
    Name::new(format!("permutation_last_{idx}"))
}

fn lookup_permuted_input_name(idx: usize) -> Name {
    Name::new(format!("lookup_{idx}_permuted_input"))
}

fn lookup_permuted_table_name(idx: usize) -> Name {
    Name::new(format!("lookup_{idx}_permuted_table"))
}

fn lookup_product_name(idx: usize) -> Name {
    Name::new(format!("lookup_{idx}_product"))
}

fn lookup_product_eval_name(idx: usize) -> Name {
    Name::new(format!("lookup_{idx}_product_eval"))
}

fn lookup_product_next_name(idx: usize) -> Name {
    Name::new(format!("lookup_{idx}_product_next"))
}

fn lookup_input_eval_name(idx: usize) -> Name {
    Name::new(format!("lookup_{idx}_input_eval"))
}

fn lookup_input_prev_eval_name(idx: usize) -> Name {
    Name::new(format!("lookup_{idx}_input_prev_eval"))
}

fn lookup_table_eval_name(idx: usize) -> Name {
    Name::new(format!("lookup_{idx}_table_eval"))
}

fn h_commitment_name(idx: usize) -> Name {
    Name::new(format!("h_{idx}"))
}

fn snake_to_lower_camel(value: &str) -> String {
    let mut segments = value.split('_');
    let mut result = segments.next().unwrap_or_default().to_string();
    for segment in segments {
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            result.push(first.to_ascii_uppercase());
            result.extend(chars);
        }
    }
    result
}

fn column_kind(column_type: &Any) -> Result<ColumnKind> {
    match column_type {
        Any::Advice(_) => Ok(ColumnKind::Advice),
        Any::Fixed => Ok(ColumnKind::Fixed),
        Any::Instance => Ok(ColumnKind::Instance),
    }
}

fn scalar_hex(scalar: BlsFr) -> String {
    hex::encode(scalar.to_repr())
}

fn g1_hex(point: G1Affine) -> String {
    hex::encode(point.to_bytes())
}

fn g2_hex(point: G2Affine) -> String {
    hex::encode(point.to_bytes())
}

fn reverse_hex_bytes(hex_value: &str) -> Result<String> {
    ensure!(hex_value.len() % 2 == 0, "hex string has odd length");
    let mut bytes = hex::decode(hex_value).context("failed to decode hex bytes")?;
    bytes.reverse();
    Ok(hex::encode(bytes))
}
