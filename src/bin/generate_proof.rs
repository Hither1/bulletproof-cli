#![allow(non_snake_case)]

extern crate clap;
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate rand;
extern crate merlin;

use clap::{Arg,App,SubCommand};
use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use std::fs::File;
use std::io::prelude::*;
use std::env;
use std::path::Path;

/// A proof-of-shuffle.
struct ShuffleProof(R1CSProof);

impl ShuffleProof {
    fn gadget<CS: RandomizableConstraintSystem>(cs: &mut CS, x: Vec<Variable>, y: Vec<Variable>) -> Result<(),R1CSError> {

        assert_eq!(x.len(), y.len());
        let k = x.len();

        if k == 1 {
            cs.constrain(y[0] - x[0]);
            return Ok(());
        }

        cs.specify_randomized_constraints(move |cs| {
            let z = cs.challenge_scalar(b"shuffle challenge");

            // Make last x multiplier for i = k-1 and k-2
            let (_, _, last_mulx_out) = cs.multiply(x[k - 1] - z, x[k - 2] - z);

            // Make multipliers for x from i == [0, k-3]
            let first_mulx_out = (0..k - 2).rev().fold(last_mulx_out, |prev_out, i| {
                let (_, _, o) = cs.multiply(prev_out.into(), x[i] - z);
                o
            });

            // Make last y multiplier for i = k-1 and k-2
            let (_, _, last_muly_out) = cs.multiply(y[k - 1] - z, y[k - 2] - z);

            // Make multipliers for y from i == [0, k-3]
            let first_muly_out = (0..k - 2).rev().fold(last_muly_out, |prev_out, i| {
                let (_, _, o) = cs.multiply(prev_out.into(), y[i] - z);
                o
            });

            // Constrain last x mul output and last y mul output to be equal
            cs.constrain(first_mulx_out - first_muly_out);

            Ok(())
        })
    }
}

impl ShuffleProof {
    /// Attempt to construct a proof that `output` is a permutation of `input`.
    ///
    /// Returns a tuple `(proof, input_commitments || output_commitments)`.
    pub fn prove<'a, 'b>(
        pc_gens: &'b PedersenGens,
        bp_gens: &'b BulletproofGens,
        transcript: &'a mut Transcript,
        input: &[Scalar],
        output: &[Scalar],
    ) -> Result<(ShuffleProof, Vec<CompressedRistretto>, Vec<CompressedRistretto>), R1CSError> {
        // Apply a domain separator with the shuffle parameters to the transcript
        let k = input.len();
        transcript.commit_bytes(b"dom-sep", b"ShuffleProof");
        transcript.commit_bytes(b"k", Scalar::from(k as u64).as_bytes());

        let mut prover = Prover::new(&pc_gens, transcript);

        // Construct blinding factors using an RNG.
        // Note: a non-example implementation would want to operate on existing commitments.
        let mut blinding_rng = rand::thread_rng();

        let (input_commitments, input_vars): (Vec<_>, Vec<_>) = input.into_iter()
            .map(|v| {
                prover.commit(*v, Scalar::random(&mut blinding_rng))
            })
            .unzip();

        let (output_commitments, output_vars): (Vec<_>, Vec<_>) = output.into_iter()
            .map(|v| {
                prover.commit(*v, Scalar::random(&mut blinding_rng))
            })
            .unzip();

        ShuffleProof::gadget(&mut prover, input_vars, output_vars)?;

        let proof = prover.prove(&bp_gens)?;

        Ok((ShuffleProof(proof), input_commitments, output_commitments))
    }
}

impl ShuffleProof {
    /// Attempt to verify a `ShuffleProof`.
    pub fn verify<'a, 'b>(
        &self,
        pc_gens: &'b PedersenGens,
        bp_gens: &'b BulletproofGens,
        transcript: &'a mut Transcript,
        input_commitments: &Vec<CompressedRistretto>,
        output_commitments: &Vec<CompressedRistretto>,
    ) -> Result<(), R1CSError> {
        // Apply a domain separator with the shuffle parameters to the transcript
        let k = input_commitments.len();
        transcript.commit_bytes(b"dom-sep", b"ShuffleProof");
        transcript.commit_bytes(b"k", Scalar::from(k as u64).as_bytes());

        let mut verifier = Verifier::new(transcript);

        let input_vars: Vec<_> = input_commitments.iter().map(|commitment| {
            verifier.commit(*commitment)
        }).collect();

        let output_vars: Vec<_> = output_commitments.iter().map(|commitment| {
            verifier.commit(*commitment)
        }).collect();

        ShuffleProof::gadget(&mut verifier, input_vars, output_vars)?;

        verifier.verify(&self.0, &pc_gens, &bp_gens)
    }
}

fn main() {
    let matches = App::new("bulletproof")
    .version("0.1.0")
    .author("Huangyuan.Su")
    .about("Bulletproof CLI")
    .arg(Arg::with_name("iArg")
        .short("i")
        .long("genPath")
        .help("file path of generators")
        .takes_value(true)
        .number_of_values(2))
    .arg(Arg::with_name("pArg")
        .short("p")
        .long("provingkeyPath")
        .help("file path of proving key")
        .takes_value(true))
    .arg(Arg::with_name("Repository")
        .short("j")
        .long("outputRepository")
        .help("path to the output repository"))
    .get_matches();


    // If file path to generators is present
    if let Some(genPath) = matche.values_of("iArg"){
        let pri_key: u64 = vec[0].parse().unwrap();
        let asset_token: u64 = vec[1].parse().unwrap();

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(1024, 1);

        let (proof, in_commitments, out_commitments) = {
            let inputs = [
                Scalar::from(pri_key),
            ];
        let outputs = [
            Scalar::from(asset_token),
        ];

        let mut prover_transcript = Transcript::new(b"ShuffleProofTest");
        ShuffleProof::prove(
            &pc_gens,
            &bp_gens,
            &mut prover_transcript,
            &inputs,
            &outputs,
        )
        .expect("error during proving")
        };

        // Change to the Path of genPath
        let current = Path::new(genPath);
        assert!(env::set_current_dir(&current).is_ok());

        // Create file for Pederson generator & write into it
        let mut f_pc = File::create("pc_gens")?;
        f_pc.write_all(pc_gens);

        // Create file for Bulletproof generator & write into it
        let mut f_bp = File::create("bp_gens")?;
        f_bp.write_all(bp_gens);

        // Create file for generated proof & write into it
        let mut f_proof = File::create("")?;
        f_proof.write_all(b"Hello, world!");

        let mut verifier_transcript = Transcript::new(b"ShuffleProofTest");
        assert!(
            proof
                .verify(&pc_gens, &bp_gens, &mut verifier_transcript, &in_commitments, &out_commitments)
                .is_ok()
        );
    };

}
