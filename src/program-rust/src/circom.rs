use serde_json;
use serde::Deserialize;
use std::str::FromStr;
use ark_bn254::{Bn254, G1Affine, G2Affine, G2Projective, G1Projective, Fq, Fq2, Fr};

#[derive(Debug, Deserialize)]
pub struct RawPublicParams {
    #[serde(rename = "inputs")]
    raw_public_params: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RawCircuitProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
    protocol: String,
    curve: String,
}

#[derive(Debug, Deserialize)]
pub struct RawVerificationKey {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    num_public: u64,
    vk_alpha_1: Vec<String>,
    vk_beta_2: Vec<Vec<String>>,
    vk_gamma_2: Vec<Vec<String>>,
    vk_delta_2: Vec<Vec<String>>,
    vk_alphabeta_12: Vec<Vec<Vec<String>>>,
    #[serde(rename = "IC")]
    ic: Vec<Vec<String>>,
}

#[derive(Debug)]
pub struct CircuitProof {
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
}

#[derive(Debug)]
pub struct CircuitPublicParams {
    public_params: Vec<Fr>,
}

#[derive(Debug)]
pub struct CircuitVerifyingKey {
    alpha_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g2: G2Affine,
    gamma_abc_g1: Vec<G1Affine>
}

fn fq_from_str(s: String) -> Fq {
    return Fq::from_str(&s).unwrap();
}

pub fn fr_from_str (s: String) -> Fr {
    return Fr::from_str(&s).unwrap();
}

pub fn g1_from_str(g1: &Vec<String>) -> G1Affine {
    let x = fq_from_str(g1[0].clone());
    let y = fq_from_str(g1[1].clone());
    let z = fq_from_str(g1[2].clone());
    return G1Affine::from(G1Projective::new(x, y, z));
}

pub fn g2_from_str(g2: &Vec<Vec<String>>) -> G2Affine {
    let c0 = fq_from_str(g2[0][0].clone());
    let c1 = fq_from_str(g2[0][1].clone());
    let x = Fq2::new(c0, c1);

    let c0 = fq_from_str(g2[1][0].clone());
    let c1 = fq_from_str(g2[1][1].clone());
    let y = Fq2::new(c0, c1);

    let c0 = fq_from_str(g2[2][0].clone());
    let c1 = fq_from_str(g2[2][1].clone());
    let z = Fq2::new(c0, c1);

    return G2Affine::from(G2Projective::new(x, y, z));
}

impl CircuitPublicParams {
    pub fn read_input_from_json(input_str: &str) -> Self {
        let params: RawPublicParams = serde_json::from_str(&input_str).expect("Unable to parse");
        let mut ret = Vec::new();
        for param in params.raw_public_params {
            ret.push(fr_from_str(param));
        }
        return CircuitPublicParams { public_params: ret };
    }
}

impl CircuitProof {
    pub fn read_input_from_json(input_str: &str) -> Self {
        let params: RawCircuitProof = serde_json::from_str(&input_str).expect("Unable to parse");

        // Parse pi_a
        let a: G1Affine = g1_from_str(&params.pi_a);

        // Parse pi_b
        let b: G2Affine = g2_from_str(&params.pi_b);

        // Parse pi_c
        let c: G1Affine = g1_from_str(&params.pi_c);

        return CircuitProof { a, b, c };
    }
}

impl From<CircuitProof> for ark_groth16::Proof<Bn254> {
    fn from(src: CircuitProof) -> ark_groth16::Proof<Bn254> {
        ark_groth16::Proof {
            a: src.a,
            b: src.b,
            c: src.c
        }
    }
}

impl CircuitVerifyingKey {
    pub fn read_input_from_json(input_str: &str) -> Self {
        let params: RawVerificationKey = serde_json::from_str(&input_str).expect("Unable to parse");

        let alpha_g1 = g1_from_str(&params.vk_alpha_1);
        let beta_g2 = g2_from_str(&params.vk_beta_2);
        let gamma_g2 = g2_from_str(&params.vk_gamma_2);
        let delta_g2 = g2_from_str(&params.vk_delta_2);
        let gamma_abc_g1: Vec<G1Affine> = params.ic.iter().map(|x| g1_from_str(&x)).collect();

        return CircuitVerifyingKey { alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1 }
    }
}

impl From<CircuitVerifyingKey> for ark_groth16::VerifyingKey<Bn254> {
    fn from(src: CircuitVerifyingKey) -> ark_groth16::VerifyingKey<Bn254> {
        ark_groth16::VerifyingKey {
            alpha_g1: src.alpha_g1,
            beta_g2: src.beta_g2,
            gamma_g2: src.gamma_g2,
            delta_g2: src.delta_g2,
            gamma_abc_g1: src.gamma_abc_g1.into_iter().map(Into::into).collect()
        }
    }
}

pub fn run_verifier() -> bool {
        let pub_input_str = include_str!("../circuits/public.json");
        let pub_input = CircuitPublicParams::read_input_from_json(pub_input_str);

        let proof_str = include_str!("../circuits/proof.json");
        let proof = ark_groth16::Proof::from(CircuitProof::read_input_from_json(proof_str));

        let input_str = include_str!("../circuits/verification_key.json");
        let res = CircuitVerifyingKey::read_input_from_json(input_str);
        let out = ark_groth16::VerifyingKey::from(res);
        let pvk = ark_groth16::prepare_verifying_key(&out);

        return ark_groth16::verify_proof(&pvk, &proof, &pub_input.public_params[..]).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use num_bigint::BigUint;

    #[test]
    fn test_read_public_input_from_json() {
        let input_str = "{\"inputs\": [\"33\"]}";
        let res = CircuitPublicParams::read_input_from_json(input_str);
        let expected_params = vec![Fr::from(33)];
        assert!(res.public_params == expected_params);
    }

    #[test]
    fn test_read_proof_from_json() {
        let input_str = include_str!("../circuits/proof.json");
        let params: RawCircuitProof = serde_json::from_str(&input_str).expect("Unable to parse");
        let res = CircuitProof::read_input_from_json(input_str);
        let pi_a_x_json = params.pi_a[0].parse::<BigUint>().unwrap();
        let pi_a_x_str = res.a.x.to_string();
        let pi_a_x = pi_a_x_str.trim_start_matches("Fp256 \"(0").trim_end_matches(")\"");
        let pi_a_x_json_hex = format!("{:X}", pi_a_x_json);
        assert!(pi_a_x == pi_a_x_json_hex);
        // TODO: verify other parameters as well
    }

    #[test]
    fn test_read_verification_key_from_json() {
        let res = run_verifier();
        assert!(res);
    }
}
