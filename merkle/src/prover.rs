use crate::util::{Hash32Bytes, write_merkle_proof,encode_hash, MerkleProof, hash_leaf};
use sha2::{Sha256, Digest};

fn gen_leaves_for_merkle_tree(num_leaves: usize) -> Vec<String> {
    let leaves: Vec<String> = (0..num_leaves)
        .map(|i| format!("data item {}", i))
        .collect();

    println!("\nI generated #{} leaves for a Merkle tree.", num_leaves);

    leaves
}

fn hexs(v: Hash32Bytes) -> String {
    let h = hex::encode(v);
    return h.chars().take(4).collect()
}

pub fn gen_merkle_proof(leaves: Vec<String>, leaf_pos: usize) -> Vec<Hash32Bytes> {
    let height = (leaves.len() as f64).log2().ceil() as u32;
    let padlen = (2u32.pow(height)) as usize - leaves.len();

    // hash all the leaves
    let mut state: Vec<Hash32Bytes> = leaves.into_iter().map(hash_leaf).collect();

    // Pad the list of hashed leaves to a power of two
    let zeros = [0u8; 32];
    for _ in 0..padlen {
        state.push(zeros);
    }

    for (index, value) in state.iter().enumerate() {
        println!("{}: {}", index, hexs(*value));
    }

    // initialize a vector that will contain the hashes in the proof
    let mut hashes: Vec<Hash32Bytes> = vec![];

    let mut _level_pos = leaf_pos;
    for _level in 0..height {
        // Calculate the sibling position at the current level
        let sibling_pos = if _level_pos % 2 == 0 {
            _level_pos + 1
        } else {
            _level_pos - 1
        };

        // Calculate the parent position at the next level
        let parent_pos = _level_pos / 2;

        // Combine the sibling and current node hashes to form the parent hash
        let parent_hash = combine_hashes(&state[sibling_pos], &state[_level_pos]);

        // Add the parent hash to the proof
        hashes.push(parent_hash);

        // Move to the next level
        _level_pos = parent_pos;
    }

    // Returns list of hashes that make up the Merkle Proof
    hashes
}

// Helper function to combine two hash values
fn combine_hashes(hash1: &Hash32Bytes, hash2: &Hash32Bytes) -> Hash32Bytes {
    let mut hasher = sha2::Sha256::new();
    hasher.update(hash1);
    hasher.update(hash2);
    hasher.finalize().into()
}

pub fn run(leaf_position: usize, num_leaves: usize) {
    let file_name = format!("proof_gen_{}_{}.yaml", num_leaves, leaf_position);

    let leaves = gen_leaves_for_merkle_tree(num_leaves);
    assert!(leaf_position < leaves.len());
    let leaf_value = leaves[leaf_position].clone();
    let hashes = gen_merkle_proof(leaves, leaf_position);

    let mut proof_hash_values_base64: Vec<String> = Vec::new();

    for hash in hashes {
        proof_hash_values_base64.push(encode_hash(hash))
    }

    let proof = MerkleProof{
        leaf_position,
        leaf_value,
        proof_hash_values_base64,
        proof_hash_values: None,
    };

    write_merkle_proof(&proof, &file_name)
}