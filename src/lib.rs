use std::{
    collections::HashMap,
    env::current_dir,
    fs,
    path::{Path, PathBuf},
};

use crate::circom::reader::generate_witness_from_bin;
use circom::circuit::{CircomCircuit, R1CS};
use ff::Field;
use nova_snark::{
    traits::{circuit::TrivialTestCircuit, Group},
    PublicParams, RecursiveSNARK,
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(not(target_family = "wasm"))]
use crate::circom::reader::generate_witness_from_wasm;

#[cfg(target_family = "wasm")]
use crate::circom::wasm::generate_witness_from_wasm;

pub mod circom;

pub type F<G> = <G as Group>::Scalar;
pub type EE<G> = nova_snark::provider::ipa_pc::EvaluationEngine<G>;
pub type S<G> = nova_snark::spartan::snark::RelaxedR1CSSNARK<G, EE<G>>;
pub type C1<G> = CircomCircuit<<G as Group>::Scalar>;
pub type C2<G> = TrivialTestCircuit<<G as Group>::Scalar>;

#[derive(Clone)]
pub enum FileLocation {
    PathBuf(PathBuf),
    URL(String),
}

pub fn create_public_params<G1, G2>(r1cs: R1CS<F<G1>>) -> PublicParams<G1, G2, C1<G1>, C2<G2>>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let circuit_primary = CircomCircuit {
        r1cs,
        witness: None,
    };
    let circuit_secondary = TrivialTestCircuit::default();

    PublicParams::setup(circuit_primary.clone(), circuit_secondary.clone())
}

#[derive(Serialize, Deserialize)]
struct CircomInput {
    step_in: Vec<String>,

    #[serde(flatten)]
    extra: HashMap<String, Value>,
}


#[cfg(not(target_family = "wasm"))]
fn compute_witnesscalc<G1, G2>(
    current_public_input: Vec<String>,
    private_input: HashMap<String, Value>,
    witness_generator_bin: &Path,
    witness_generator_file: &[u8],
    witness_generator_output: &Path,
) -> Vec<<G1 as Group>::Scalar>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    use std::time::{Duration, Instant};

    use circom::reader::generate_witness_from_witnesscalc;

    let decimal_stringified_input: Vec<String> = current_public_input
        .iter()
        .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
        .collect();

    let input = CircomInput {
        step_in: decimal_stringified_input.clone(),
        extra: private_input.clone(),
    };

    // let is_wasm = match &witness_generator_file {
    //     FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
    //     FileLocation::URL(_) => true,
    // };
    let input_json = serde_json::to_string(&input).unwrap();

    // if is_wasm {
    //     generate_witness_from_wasm::<F<G1>>(
    //         &witness_generator_file,
    //         &input_json,
    //         &witness_generator_output,
    //     )
    // } else {
        // let witness_generator_file = match &witness_generator_file {
        //     FileLocation::PathBuf(path) => path,
        //     FileLocation::URL(_) => panic!("unreachable"),
        // };
        // if witness_generator_bin.exists() {
            // let mut input = HashMap::<String, Vec<U256>>::new();
            // for (key, value) in private_input.iter() {
            //     let mut value_u256 = vec![];
            //     if value.is_u64() {
            //         value_u256.push(U256::from(value.as_u64().unwrap()));
            //     } else if value.is_array() {
            //         value_u256.append(
            //             &mut value
            //             .as_array()
            //             .unwrap()
            //             .iter()
            //             .map(|num| U256::from(num.as_u64().unwrap()))
            //             .collect::<Vec<U256>>()
            //         );
            //     } else {
            //         panic!("invalid value in input");
            //     }
            //     input.insert(key.clone(), value_u256);
            // }
            // let graph_bytes = std::fs::read(&witness_generator_bin).unwrap();
            // let graph = init_graph(&graph_bytes).unwrap();
            // let witness = witness::calculate_witness(input, &graph);
            // println!("witness: {:?}", witness.unwrap());
            generate_witness_from_witnesscalc::<F<G1>>(
                witness_generator_bin,
                witness_generator_file,
                &input_json,
                witness_generator_output)
        // } else {
        //     generate_witness_from_bin::<F<G1>>(
        //         &witness_generator_file,
        //         &input_json,
        //         &witness_generator_output,
        //     )
        // }
    // }
}

#[cfg(not(target_family = "wasm"))]
fn compute_witness<G1, G2>(
    current_public_input: Vec<String>,
    private_input: HashMap<String, Value>,
    witness_generator_bin: &Path,
    witness_generator_file: FileLocation,
    witness_generator_output: &Path,
) -> Vec<<G1 as Group>::Scalar>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    use circom::reader::generate_witness_from_witnesscalc;

    let decimal_stringified_input: Vec<String> = current_public_input
        .iter()
        .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
        .collect();

    let input = CircomInput {
        step_in: decimal_stringified_input.clone(),
        extra: private_input.clone(),
    };

    let is_wasm = match &witness_generator_file {
        FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
        FileLocation::URL(_) => true,
    };
    let input_json = serde_json::to_string(&input).unwrap();

    if is_wasm {
        generate_witness_from_wasm::<F<G1>>(
            &witness_generator_file,
            &input_json,
            &witness_generator_output,
        )
    } else {
        let witness_generator_file = match &witness_generator_file {
            FileLocation::PathBuf(path) => path,
            FileLocation::URL(_) => panic!("unreachable"),
        };
        if witness_generator_bin.exists() {
            // let mut input = HashMap::<String, Vec<U256>>::new();
            // for (key, value) in private_input.iter() {
            //     let mut value_u256 = vec![];
            //     if value.is_u64() {
            //         value_u256.push(U256::from(value.as_u64().unwrap()));
            //     } else if value.is_array() {
            //         value_u256.append(
            //             &mut value
            //             .as_array()
            //             .unwrap()
            //             .iter()
            //             .map(|num| U256::from(num.as_u64().unwrap()))
            //             .collect::<Vec<U256>>()
            //         );
            //     } else {
            //         panic!("invalid value in input");
            //     }
            //     input.insert(key.clone(), value_u256);
            // }
            // let graph_bytes = std::fs::read(&witness_generator_bin).unwrap();
            // let graph = init_graph(&graph_bytes).unwrap();
            // let witness = witness::calculate_witness(input, &graph);
            // println!("witness: {:?}", witness.unwrap());
            generate_witness_from_witnesscalc::<F<G1>>(
                witness_generator_bin,
                &vec![],
                &input_json,
                witness_generator_output)
        } else {
            generate_witness_from_bin::<F<G1>>(
                &witness_generator_file,
                &input_json,
                &witness_generator_output,
            )
        }
    }
}

#[cfg(target_family = "wasm")]
async fn compute_witness<G1, G2>(
    current_public_input: Vec<String>,
    private_input: HashMap<String, Value>,
    witness_generator_file: FileLocation,
) -> Vec<<G1 as Group>::Scalar>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let decimal_stringified_input: Vec<String> = current_public_input
        .iter()
        .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
        .collect();

    let input = CircomInput {
        step_in: decimal_stringified_input.clone(),
        extra: private_input.clone(),
    };

    let is_wasm = match &witness_generator_file {
        FileLocation::PathBuf(path) => path.extension().unwrap_or_default() == "wasm",
        FileLocation::URL(_) => true,
    };
    let input_json = serde_json::to_string(&input).unwrap();

    if is_wasm {
        generate_witness_from_wasm::<F<G1>>(
            &witness_generator_file,
            &input_json,
        )
        .await
    } else {
        let root = current_dir().unwrap(); // compute path only when generating witness from a binary
        let witness_generator_output = root.join("circom_witness.wtns");
        let witness_generator_file = match &witness_generator_file {
            FileLocation::PathBuf(path) => path,
            FileLocation::URL(_) => panic!("unreachable"),
        };
        generate_witness_from_bin::<F<G1>>(
            &witness_generator_file,
            &input_json,
            &witness_generator_output,
        )
    }
}


#[cfg(not(target_family = "wasm"))]
pub fn create_recursive_circuit_witnesscalc<G1, G2>(
    witness_generator_bin: &Path,
    witness_generator_file: &PathBuf,
    r1cs: R1CS<F<G1>>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F<G1>>,
    pp: &PublicParams<G1, G2, C1<G1>, C2<G2>>,
) -> Result<RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>, std::io::Error>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    use std::time::Instant;

    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let start_public_input_hex = start_public_input
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let mut current_public_input = start_public_input_hex.clone();

    let graph_bin = std::fs::read(witness_generator_file)?;

    let now = Instant::now();
    let witness_0 = compute_witnesscalc::<G1, G2>(
        current_public_input.clone(),
        private_inputs[0].clone(),
        witness_generator_bin,
        &graph_bin,
        &witness_generator_output,
    );
    println!("witness gen for iteration 0 takes: {:?}", now.elapsed());

    let circuit_0 = CircomCircuit {
        r1cs: r1cs.clone(),
        witness: Some(witness_0),
    };
    let circuit_secondary = TrivialTestCircuit::default();
    let z0_secondary = vec![G2::Scalar::ZERO];

    let mut recursive_snark = RecursiveSNARK::<G1, G2, C1<G1>, C2<G2>>::new(
        &pp,
        &circuit_0,
        &circuit_secondary,
        start_public_input.clone(),
        z0_secondary.clone(),
    );

    for i in 0..iteration_count {
        let now = Instant::now();
        let witness = compute_witnesscalc::<G1, G2>(
            current_public_input.clone(),
            private_inputs[i].clone(),
            witness_generator_bin,
            &graph_bin,
            &witness_generator_output,
        );
        println!("witness gen for iteration {} takes: {:?}", i, now.elapsed());

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let now = Instant::now();
        let res = recursive_snark.prove_step(
            &pp,
            &circuit,
            &circuit_secondary,
            start_public_input.clone(),
            z0_secondary.clone(),
        );
        assert!(res.is_ok());
        println!("proving step for iteration {} takes: {:?}", i, now.elapsed());
    }
    // TODO: remove comment
    // fs::remove_file(witness_generator_output)?;

    Ok(recursive_snark)
}

#[cfg(not(target_family = "wasm"))]
pub fn create_recursive_circuit<G1, G2>(
    witness_generator_file: FileLocation,
    r1cs: R1CS<F<G1>>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F<G1>>,
    pp: &PublicParams<G1, G2, C1<G1>, C2<G2>>,
) -> Result<RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>, std::io::Error>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let start_public_input_hex = start_public_input
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let mut current_public_input = start_public_input_hex.clone();

    let witness_0 = compute_witness::<G1, G2>(
        current_public_input.clone(),
        private_inputs[0].clone(),
        Path::new("s"),
        witness_generator_file.clone(),
        &witness_generator_output,
    );

    let circuit_0 = CircomCircuit {
        r1cs: r1cs.clone(),
        witness: Some(witness_0),
    };
    let circuit_secondary = TrivialTestCircuit::default();
    let z0_secondary = vec![G2::Scalar::ZERO];

    let mut recursive_snark = RecursiveSNARK::<G1, G2, C1<G1>, C2<G2>>::new(
        &pp,
        &circuit_0,
        &circuit_secondary,
        start_public_input.clone(),
        z0_secondary.clone(),
    );

    for i in 0..iteration_count {
        let witness = compute_witness::<G1, G2>(
            current_public_input.clone(),
            private_inputs[i].clone(),
            Path::new("s"),
            witness_generator_file.clone(),
            &witness_generator_output,
        );

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            &pp,
            &circuit,
            &circuit_secondary,
            start_public_input.clone(),
            z0_secondary.clone(),
        );
        assert!(res.is_ok());
    }
    fs::remove_file(witness_generator_output)?;

    Ok(recursive_snark)
}

#[cfg(target_family = "wasm")]
pub async fn create_recursive_circuit<G1, G2>(
    witness_generator_file: FileLocation,
    r1cs: R1CS<F<G1>>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F<G1>>,
    pp: &PublicParams<G1, G2, C1<G1>, C2<G2>>,
) -> Result<RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>, std::io::Error>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{

    let iteration_count = private_inputs.len();

    let start_public_input_hex = start_public_input
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let mut current_public_input = start_public_input_hex.clone();

    let witness_0 = compute_witness::<G1, G2>(
        current_public_input.clone(),
        private_inputs[0].clone(),
        witness_generator_file.clone(),
    )
    .await;

    let circuit_0 = CircomCircuit {
        r1cs: r1cs.clone(),
        witness: Some(witness_0),
    };
    let circuit_secondary = TrivialTestCircuit::default();
    let z0_secondary = vec![G2::Scalar::ZERO];

    let mut recursive_snark = RecursiveSNARK::<G1, G2, C1<G1>, C2<G2>>::new(
        &pp,
        &circuit_0,
        &circuit_secondary,
        start_public_input.clone(),
        z0_secondary.clone(),
    );

    for i in 0..iteration_count {
        let witness = compute_witness::<G1, G2>(
            current_public_input.clone(),
            private_inputs[i].clone(),
            witness_generator_file.clone(),
        )
        .await;

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            &pp,
            &circuit,
            &circuit_secondary,
            start_public_input.clone(),
            z0_secondary.clone(),
        );
        assert!(res.is_ok());
    }

    Ok(recursive_snark)
}

#[cfg(not(target_family = "wasm"))]
pub fn continue_recursive_circuit<G1, G2>(
    recursive_snark: &mut RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>,
    last_zi: Vec<F<G1>>,
    witness_generator_file: FileLocation,
    r1cs: R1CS<F<G1>>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F<G1>>,
    pp: &PublicParams<G1, G2, C1<G1>, C2<G2>>,
) -> Result<(), std::io::Error>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let mut current_public_input = last_zi
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();

    let circuit_secondary = TrivialTestCircuit::default();
    let z0_secondary = vec![G2::Scalar::ZERO];

    for i in 0..iteration_count {
        let witness = compute_witness::<G1, G2>(
            current_public_input.clone(),
            private_inputs[i].clone(),
            Path::new("s"),
            witness_generator_file.clone(),
            &witness_generator_output,
        );

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            pp,
            &circuit,
            &circuit_secondary,
            start_public_input.clone(),
            z0_secondary.clone(),
        );

        assert!(res.is_ok());
    }

    fs::remove_file(witness_generator_output)?;

    Ok(())
}

#[cfg(target_family = "wasm")]
pub async fn continue_recursive_circuit<G1, G2>(
    recursive_snark: &mut RecursiveSNARK<G1, G2, C1<G1>, C2<G2>>,
    last_zi: Vec<F<G1>>,
    witness_generator_file: FileLocation,
    r1cs: R1CS<F<G1>>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F<G1>>,
    pp: &PublicParams<G1, G2, C1<G1>, C2<G2>>,
) -> Result<(), std::io::Error>
where
    G1: Group<Base = <G2 as Group>::Scalar>,
    G2: Group<Base = <G1 as Group>::Scalar>,
{
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let mut current_public_input = last_zi
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();

    let circuit_secondary = TrivialTestCircuit::default();
    let z0_secondary = vec![G2::Scalar::ZERO];

    for i in 0..iteration_count {
        let witness = compute_witness::<G1, G2>(
            current_public_input.clone(),
            private_inputs[i].clone(),
            witness_generator_file.clone(),
        )
        .await;

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            pp,
            &circuit,
            &circuit_secondary,
            start_public_input.clone(),
            z0_secondary.clone(),
        );

        assert!(res.is_ok());
    }

    fs::remove_file(witness_generator_output)?;

    Ok(())
}
