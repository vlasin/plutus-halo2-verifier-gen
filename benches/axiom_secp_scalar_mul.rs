use std::{
    env,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

mod cardano_transcript;

use cardano_transcript::{CardanoBlake2bRead, CardanoBlake2bWrite};
use halo2_base::{
    Context,
    gates::{
        RangeChip,
        circuit::{BaseCircuitParams, CircuitBuilderStage, builder::RangeCircuitBuilder},
    },
    halo2_proofs::{
        halo2curves::{
            bls12_381::{Bls12, Fr as BlsFr, G1Affine},
            ff::Field,
            group::Curve,
            secp256k1::{Fq, Secp256k1Affine},
        },
        plonk::{Circuit, ProvingKey, create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
    },
    utils::{BigPrimeField, fe_to_biguint},
};
use halo2_ecc::{
    ecc::EccChip,
    fields::FieldChip,
    secp256k1::{FpChip, FqChip},
};
use plutus_halo2_verifier_gen::plutus_gen::generate_axiom_shplonk_verifiers_from_vk;
use rand::{SeedableRng, rngs::StdRng};
use serde_json::Value;

const AIKEN_BENCHMARK_NAME: &str = "valid_axiom_shplonk_proof_benchmark";
const PLINTH_BENCHMARK_GHC_VERSION: &str = "9.6.7";
const PLINTH_BUDGET_LABEL: &str = "Axiom SHPLONK Plinth verifier budget:";

#[derive(Clone, Copy, Debug)]
struct ScalarMulParams {
    degree: u32,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    window_bits: usize,
    unusable_rows: usize,
}

#[derive(Debug)]
struct CircuitStats {
    total_advice_cells: usize,
    enabled_gate_constraints: usize,
    total_lookup_cells: usize,
    total_fixed_cells: usize,
    config_params: BaseCircuitParams,
}

fn main() {
    let params = ScalarMulParams {
        degree: 18,
        lookup_bits: 17,
        limb_bits: 88,
        num_limbs: 3,
        window_bits: 4,
        unusable_rows: 9,
    };

    let mut rng = StdRng::seed_from_u64(0);
    let base = Secp256k1Affine::random(&mut rng);
    let scalar = Fq::random(&mut rng);

    let total_start = Instant::now();
    let (keygen_builder, stats) = build_keygen_circuit(params, base, scalar);

    let setup_start = Instant::now();
    let kzg_params = ParamsKZG::<Bls12>::setup(params.degree, StdRng::seed_from_u64(2));
    let setup_time = setup_start.elapsed();

    let vk_start = Instant::now();
    let vk = keygen_vk(&kzg_params, &keygen_builder).expect("vkey generation should succeed");
    let vk_time = vk_start.elapsed();

    let pk_start = Instant::now();
    let pk = keygen_pk(&kzg_params, vk, &keygen_builder).expect("pkey generation should succeed");
    let pk_time = pk_start.elapsed();

    let break_points = keygen_builder.break_points();
    let config_params = stats.config_params.clone();
    drop(keygen_builder);

    let witness_start = Instant::now();
    let prover_builder = build_prover_circuit(config_params, break_points, params, base, scalar);
    let witness_time = witness_start.elapsed();

    let proof_start = Instant::now();
    let proof = gen_proof(&kzg_params, &pk, prover_builder);
    let proof_time = proof_start.elapsed();

    let verify_start = Instant::now();
    verify(&kzg_params, &pk, &proof);
    let verify_time = verify_start.elapsed();

    let generator_start = Instant::now();
    generate_axiom_shplonk_verifiers_from_vk(&kzg_params, pk.get_vk(), &proof)
        .expect("Axiom SHPLONK verifier generation should succeed");
    let generator_time = generator_start.elapsed();

    println!(
        "backend: Axiom halo2-axiom, BLS12-381 KZG, SHPLONK, Cardano-friendly Blake2b transcript"
    );
    println!(
        "circuit: secp256k1 variable-base scalar multiplication, limb_bits={}, num_limbs={}, window_bits={}",
        params.limb_bits, params.num_limbs, params.window_bits
    );
    println!(
        "shape: k={}, usable_rows={}, advice={:?}, lookup_advice={:?}, fixed={}, lookup_bits={:?}",
        stats.config_params.k,
        (1usize << stats.config_params.k) - params.unusable_rows,
        stats.config_params.num_advice_per_phase,
        stats.config_params.num_lookup_advice_per_phase,
        stats.config_params.num_fixed,
        stats.config_params.lookup_bits
    );
    println!("total_advice_cells: {}", stats.total_advice_cells);
    println!(
        "enabled_gate_constraints: {}",
        stats.enabled_gate_constraints
    );
    println!("total_lookup_cells: {}", stats.total_lookup_cells);
    println!("total_fixed_cells: {}", stats.total_fixed_cells);
    println!("proof_size_bytes: {}", proof.len());
    println!("setup_time: {}", fmt_duration(setup_time));
    println!("vk_time: {}", fmt_duration(vk_time));
    println!("pk_time: {}", fmt_duration(pk_time));
    println!("witness_time: {}", fmt_duration(witness_time));
    println!("proof_time: {}", fmt_duration(proof_time));
    println!("verify_time: {}", fmt_duration(verify_time));
    println!("generic_generator_time: {}", fmt_duration(generator_time));

    let aiken_start = Instant::now();
    let aiken_output = run_aiken_check();
    let aiken_time = aiken_start.elapsed();
    let (mem, cpu) = parse_aiken_budget(&aiken_output, AIKEN_BENCHMARK_NAME)
        .expect("Aiken benchmark ExUnits should be present in aiken check output");
    println!("aiken_benchmark: {AIKEN_BENCHMARK_NAME}");
    println!("aiken_mem: {mem}");
    println!("aiken_cpu: {cpu}");
    println!("aiken_check_time: {}", fmt_duration(aiken_time));

    let plinth_start = Instant::now();
    let plinth_output = run_plinth_benchmark();
    let plinth_time = plinth_start.elapsed();
    let (mem, cpu) = parse_plinth_budget(&plinth_output, PLINTH_BUDGET_LABEL)
        .expect("Plinth benchmark ExUnits should be present in cabal test output");
    println!("plinth_benchmark: Axiom SHPLONK proof verification in Plutus");
    println!("plinth_mem: {mem}");
    println!("plinth_cpu: {cpu}");
    println!("plinth_test_time: {}", fmt_duration(plinth_time));
    println!("total_time: {}", fmt_duration(total_start.elapsed()));
}

fn build_keygen_circuit(
    params: ScalarMulParams,
    base: Secp256k1Affine,
    scalar: Fq,
) -> (RangeCircuitBuilder<BlsFr>, CircuitStats) {
    let mut builder =
        RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen).use_k(params.degree as usize);
    builder.set_lookup_bits(params.lookup_bits);
    let range = builder.range_chip();
    run_scalar_mul(builder.main(0), &range, params, base, scalar);

    let raw_stats = builder.statistics();
    let total_advice_cells = raw_stats.gate.total_advice_per_phase.iter().sum();
    let total_lookup_cells = raw_stats.total_lookup_advice_per_phase.iter().sum();
    let total_fixed_cells = raw_stats.gate.total_fixed;
    let enabled_gate_constraints = builder
        .core()
        .phase_manager
        .iter()
        .flat_map(|phase| phase.threads.iter())
        .map(|ctx| ctx.selector.iter().filter(|enabled| **enabled).count())
        .sum();

    let config_params = builder.calculate_params(Some(params.unusable_rows));
    let stats = CircuitStats {
        total_advice_cells,
        enabled_gate_constraints,
        total_lookup_cells,
        total_fixed_cells,
        config_params,
    };
    (builder, stats)
}

fn build_prover_circuit(
    config_params: BaseCircuitParams,
    break_points: Vec<Vec<usize>>,
    params: ScalarMulParams,
    base: Secp256k1Affine,
    scalar: Fq,
) -> RangeCircuitBuilder<BlsFr> {
    let mut builder = RangeCircuitBuilder::prover(config_params, break_points);
    builder.set_lookup_bits(params.lookup_bits);
    let range = builder.range_chip();
    run_scalar_mul(builder.main(0), &range, params, base, scalar);
    builder
}

fn run_scalar_mul<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: ScalarMulParams,
    base: Secp256k1Affine,
    scalar: Fq,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    let scalar_assigned = fq_chip.load_private(ctx, scalar);
    let base_assigned = ecc_chip.assign_point(ctx, base);
    let product = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        base_assigned,
        scalar_assigned.limbs().to_vec(),
        fq_chip.limb_bits,
        params.window_bits,
    );

    let expected = (base * scalar).to_affine();
    assert_eq!(product.x.value(), fe_to_biguint(&expected.x));
    assert_eq!(product.y.value(), fe_to_biguint(&expected.y));
}

fn gen_proof<C>(params: &ParamsKZG<Bls12>, pk: &ProvingKey<G1Affine>, circuit: C) -> Vec<u8>
where
    C: Circuit<BlsFr>,
{
    let rng = StdRng::seed_from_u64(1);
    let instances: &[&[BlsFr]] = &[];
    let mut transcript = CardanoBlake2bWrite::<_, G1Affine>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bls12>,
        ProverSHPLONK<'_, Bls12>,
        Challenge255<_>,
        _,
        CardanoBlake2bWrite<Vec<u8>, G1Affine>,
        _,
    >(params, pk, &[circuit], &[instances], rng, &mut transcript)
    .expect("proof generation should succeed");
    transcript.finalize()
}

fn verify(params: &ParamsKZG<Bls12>, pk: &ProvingKey<G1Affine>, proof: &[u8]) {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let instances: &[&[BlsFr]] = &[];
    let mut transcript = CardanoBlake2bRead::<_, G1Affine>::init(proof);
    verify_proof::<
        KZGCommitmentScheme<Bls12>,
        VerifierSHPLONK<'_, Bls12>,
        Challenge255<G1Affine>,
        CardanoBlake2bRead<&[u8], G1Affine>,
        SingleStrategy<'_, Bls12>,
    >(
        verifier_params,
        pk.get_vk(),
        strategy,
        &[instances],
        &mut transcript,
    )
    .expect("proof verification should succeed");
}

fn run_aiken_check() -> String {
    let output = Command::new("aiken")
        .arg("check")
        .arg(".")
        .current_dir("aiken-verifier/aiken_halo2")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("aiken check should start");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        print!("{stdout}");
        eprint!("{stderr}");
    } else if !stderr.trim().is_empty() {
        eprint!("{stderr}");
    }
    assert!(output.status.success(), "aiken check should pass");
    stdout.into_owned()
}

fn parse_aiken_budget(output: &str, benchmark_name: &str) -> Option<(String, String)> {
    if let Some(budget) = parse_aiken_json_budget(output, benchmark_name) {
        return Some(budget);
    }

    let lines: Vec<_> = output.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if !line.contains(benchmark_name) {
            continue;
        }

        let window = lines[idx..lines.len().min(idx + 8)].join(" ");
        let mem = parse_metric(&window, "mem:")?;
        let cpu = parse_metric(&window, "cpu:")?;
        return Some((mem, cpu));
    }
    None
}

fn parse_aiken_json_budget(output: &str, benchmark_name: &str) -> Option<(String, String)> {
    let json: Value = serde_json::from_str(output).ok()?;
    let modules = json.get("modules")?.as_array()?;
    for module in modules {
        let tests = module.get("tests")?.as_array()?;
        for test in tests {
            if test.get("title")?.as_str()? != benchmark_name {
                continue;
            }

            let execution_units = test.get("execution_units")?;
            let mem = execution_units.get("mem")?.as_u64()?.to_string();
            let cpu = execution_units.get("cpu")?.as_u64()?.to_string();
            return Some((mem, cpu));
        }
    }
    None
}

fn parse_metric(text: &str, label: &str) -> Option<String> {
    let after = text.split(label).nth(1)?;
    let value: String = after
        .chars()
        .skip_while(|char| char.is_whitespace())
        .take_while(|char| char.is_ascii_digit() || *char == '_')
        .collect();
    (!value.is_empty()).then_some(value)
}

fn run_plinth_benchmark() -> String {
    let ghc_version =
        env::var("PLINTH_GHC_VERSION").unwrap_or_else(|_| PLINTH_BENCHMARK_GHC_VERSION.to_string());
    let output = Command::new("ghcup")
        .arg("run")
        .arg("--ghc")
        .arg(&ghc_version)
        .arg("--")
        .arg("cabal")
        .arg("test")
        .arg("axiom-shplonk-test")
        .arg("--test-show-details=direct")
        .current_dir("plinth-verifier")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Plinth benchmark command should start");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        print!("{stdout}");
        eprint!("{stderr}");
    } else if !stderr.trim().is_empty() {
        eprint!("{stderr}");
    }
    assert!(output.status.success(), "Plinth benchmark should pass");
    stdout.into_owned()
}

fn parse_plinth_budget(output: &str, label: &str) -> Option<(String, String)> {
    let line = output.lines().find(|line| line.contains(label))?;
    let mem = parse_metric(line, "ExMemory")?;
    let cpu = parse_metric(line, "ExCPU")?;
    Some((mem, cpu))
}

fn fmt_duration(duration: Duration) -> String {
    format!("{:.3}s", duration.as_secs_f64())
}
