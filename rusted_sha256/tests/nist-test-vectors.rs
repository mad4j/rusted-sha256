use std::fmt::Write;

use rusted_sha256::Sha256;

fn to_hex(data: &[u8; 32]) -> String {
    let mut s = String::new();

    for &b in data {
        write!(s, "{:02X}", b).unwrap();
    }

    s
}

#[test]
fn test_nist_byteoriented_000() {
    assert_eq!(
        to_hex(&Sha256::digest(b"")),
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    )
}
