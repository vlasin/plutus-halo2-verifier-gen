//! Extraction scaffolding for Axiom's SHPLONK KZG PCS.
//!
//! The existing generator is built around the IOG Halo2 fork and `blstrs`
//! verifier-key types. Axiom Halo2 uses a different proof-system crate and
//! curve type stack, so this module only records the SHPLONK proof-tail shape
//! and query grouping needed by a future Axiom-specific extractor/template.

use crate::plutus_gen::extraction::data::CircuitRepresentation;

use super::{ExtractPCS, PCSType};

use halo2_axiom::halo2curves::bls12_381::Bls12;
use halo2_axiom::poly::kzg::commitment::KZGCommitmentScheme;

type AxiomSHPLONKScheme = KZGCommitmentScheme<Bls12>;

/// Axiom SHPLONK verifier data needed by the generated PCS verifier.
#[derive(Default)]
pub struct AxiomSHPLONKData {
    rotation_set_count: usize,
    super_point_count: usize,
}

/// Axiom SHPLONK proof-tail steps after the ordinary PLONK evaluations.
#[derive(PartialEq, Clone, Debug)]
pub enum AxiomSHPLONKSteps {
    Y,
    V,
    H1,
    U,
    H2,
}

impl ExtractPCS for AxiomSHPLONKScheme {
    type PCSExtractionSteps = AxiomSHPLONKSteps;
    type PCSData = AxiomSHPLONKData;

    fn pcs_type() -> PCSType {
        PCSType::AxiomSHPLONK
    }

    fn pcs_data(circuit_repr: &CircuitRepresentation<Self>) -> usize {
        circuit_repr.pcs_instantiation_data.rotation_set_count
    }

    fn pcs_data_aiken(circuit_repr: &CircuitRepresentation<Self>) -> String {
        format!(
            "rotation_sets={}, super_points={}",
            circuit_repr.pcs_instantiation_data.rotation_set_count,
            circuit_repr.pcs_instantiation_data.super_point_count
        )
    }

    fn pcs_data_plinth(circuit_repr: &CircuitRepresentation<Self>) -> String {
        Self::pcs_data_aiken(circuit_repr)
    }

    fn extract_pcs(circuit_repr: &mut CircuitRepresentation<Self>) {
        let (rotation_sets, commitment_data) = Self::precompute_intermediate_sets(circuit_repr);
        circuit_repr.pcs_instantiation_data.rotation_set_count = rotation_sets.len();
        circuit_repr.pcs_instantiation_data.super_point_count = commitment_data
            .iter()
            .flat_map(|commitment| commitment.points.iter())
            .cloned()
            .collect::<std::collections::HashSet<_>>()
            .len();

        circuit_repr.pcs_extraction_steps.push(AxiomSHPLONKSteps::Y);
        circuit_repr.pcs_extraction_steps.push(AxiomSHPLONKSteps::V);
        circuit_repr
            .pcs_extraction_steps
            .push(AxiomSHPLONKSteps::H1);
        circuit_repr.pcs_extraction_steps.push(AxiomSHPLONKSteps::U);
        circuit_repr
            .pcs_extraction_steps
            .push(AxiomSHPLONKSteps::H2);
    }

    fn step_to_aiken(step: Self::PCSExtractionSteps, _number: usize) -> String {
        match step {
            AxiomSHPLONKSteps::Y => {
                "    let (shplonk_y, transcript) = squeeze_challenge(transcript)\n".to_string()
            }
            AxiomSHPLONKSteps::V => {
                "    let (v, transcript) = squeeze_challenge(transcript)\n".to_string()
            }
            AxiomSHPLONKSteps::H1 => {
                "    let (h1, transcript) = read_point(transcript)\n".to_string()
            }
            AxiomSHPLONKSteps::U => {
                "    let (u, transcript) = squeeze_challenge(transcript)\n".to_string()
            }
            AxiomSHPLONKSteps::H2 => {
                "    let (h2, transcript) = read_point(transcript)\n".to_string()
            }
        }
    }

    fn step_to_plinth(step: Self::PCSExtractionSteps, _number: usize) -> String {
        match step {
            AxiomSHPLONKSteps::Y => "  !shplonk_y <- M.squeezeChallenge\n".to_string(),
            AxiomSHPLONKSteps::V => "  !v <- M.squeezeChallenge\n".to_string(),
            AxiomSHPLONKSteps::H1 => "  !h1 <- M.readPoint\n".to_string(),
            AxiomSHPLONKSteps::U => "  !u <- M.squeezeChallenge\n".to_string(),
            AxiomSHPLONKSteps::H2 => "  !h2 <- M.readPoint\n".to_string(),
        }
    }
}
